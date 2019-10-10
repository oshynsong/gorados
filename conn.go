// conn.go - define the low-level network connection facility to rados cluster

package gorados

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultReadTimeout  = 60 * time.Second
	defaultWriteTimeout = 60 * time.Second
)

// radosConnStateType defines the connection state of the private prpotocol for RADOS.
type radosConnStateType uint8

const (
	radosConnStateInvalid = radosConnStateType(iota)
	radosConnStateConnecting
	radosConnStateAuthenticating
	radosConnStateOpen
	radosConnStateClosed
)

var (
	globalSequence   uint32
	MessageQueueSize int = 10
)

// radosConn stands for a low-level transport connection to the RADOS cluster. It fullfils the
// private protocol to communicate with RADOS cluster which only support TCP. It implements the
// net.Conn interface for extention.
type radosConn struct {
	// conn lays on the OS network stack which only support the TCP network.
	conn *net.TCPConn

	ctx        context.Context
	dialer     *net.Dialer
	remoteAddr *net.TCPAddr
	localAddr  *net.TCPAddr
	state      radosConnStateType
	lock       *sync.Mutex
	cond       *sync.Cond
	sendChan   chan Message
	recvChan   chan Message
	wg         sync.WaitGroup
	moncmdLock *sync.Mutex

	serverEntityAddr  *EntityAddr
	clientEntityAddr  *EntityAddr
	nonce             uint32 // the random number generated for the current connection.
	globalSeq         uint32
	connectSeq        uint32
	connectEntity     uint32
	outSeq            uint64
	outAckedSeq       uint64
	inSeq             uint64
	inAckedSeq        uint64
	negotiation       *NegotiationType
	negotiationReply  *NegotiationReplyType
	needSendKeepalive bool
	cryptoKey         *CryptoKey
	clientEnt         EntityName

	// Store the following critical fields that got from the remote server.
	keepalive        Time
	monmap           *monmapType
	globalId         uint64
	clientChallenge  uint64
	serverChallenge  uint64
	sessionTicket    authSessionTicket
	principalTickets []authSessionTicket

	// ReadTimeout control the timeout span for a single read.
	ReadTimeout time.Duration

	// ReadTimeout control the timeout span for a single write.
	WriteTimeout time.Duration

	// DialTimeout is the duration for dialing which user can set in external.
	// Must be set before calling connect method.
	DialTimeout time.Duration
}

// NewRadosConn creates a empty connection which can act as a handle all next operations. The
// only required argument is the entity protocol version type to be connected. Use the constants
// defined in this package to specify: MON or OSD.
func NewRadosConn(ctx context.Context, entityToConnect ConnectEntity) *radosConn {
	conn := &radosConn{
		ctx:              ctx,
		dialer:           &net.Dialer{},
		state:            radosConnStateInvalid,
		lock:             &sync.Mutex{},
		sendChan:         make(chan Message, MessageQueueSize),
		recvChan:         make(chan Message, MessageQueueSize),
		moncmdLock:       &sync.Mutex{},
		serverEntityAddr: &EntityAddr{},
		clientEntityAddr: &EntityAddr{},
		connectEntity:    uint32(entityToConnect),
		clientEnt:        EntityName{ENTITY_CLIENT, -1},
		ReadTimeout:      defaultReadTimeout,
		WriteTimeout:     defaultWriteTimeout,
	}
	conn.cond = sync.NewCond(conn.lock)
	return conn
}

func (c *radosConn) Dial(network, addr string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	remoteAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return err
	}
	c.remoteAddr = remoteAddr

	// Set the dialer parameters before creating the connection
	if c.dialer == nil {
		c.dialer = &net.Dialer{}
	}
	if c.DialTimeout > 0 {
		c.dialer.Timeout = c.DialTimeout
	}
	if c.localAddr != nil {
		c.dialer.LocalAddr = c.localAddr
	}

	// Do dialing to the rados cluster
	conn, err := c.dialer.DialContext(c.ctx, network, addr)
	if err != nil {
		return err
	}
	if tcp, ok := conn.(*net.TCPConn); !ok {
		return fmt.Errorf("only support TCP network to rados")
	} else {
		c.conn = tcp
		if c.localAddr == nil {
			c.localAddr = tcp.LocalAddr().(*net.TCPAddr)
		}
	}
	log.Printf("dial to server %s success", remoteAddr)

	c.conn.SetLinger(0) // discards remaining data when close the connection
	c.conn.SetNoDelay(true)
	c.conn.SetKeepAlive(true)
	c.conn.SetKeepAlivePeriod(10 * time.Second)
	c.state = radosConnStateConnecting
	return nil
}

// Connect implements the private handshake protocol to RADOS cluster.
func (c *radosConn) Connect(keyring string, prepare bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic error: %v", r)
		}
		if err != nil { // close the connection if error occurs
			c.Close()
		}
	}()
	if c.state != radosConnStateConnecting {
		return fmt.Errorf("connection state is invalid")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyring)
	if err != nil {
		return err
	}
	c.cryptoKey = &CryptoKey{}
	if err = c.cryptoKey.UnmarshalBinary(keyBytes); err != nil {
		return err
	}

	serverHandshakeSize := BANNER_SIZE + c.serverEntityAddr.Size() + c.clientEntityAddr.Size()
	serverHandshake := make([]byte, serverHandshakeSize)
	n, err := c.Read(serverHandshake)
	if err != nil {
		return err
	}
	if n != len(serverHandshake) {
		return fmt.Errorf("invalid server handshake")
	}
	log.Printf("read server handshake success, size=%d", n)

	// Check banner
	if !bytes.Equal(serverHandshake[0:BANNER_SIZE], []byte(BANNER_STR)) {
		err = fmt.Errorf("server banner not match: %s", string(serverHandshake[0:BANNER_SIZE]))
		return err
	}
	serverHandshake = serverHandshake[BANNER_SIZE:]
	log.Printf("check server handshake banner matched")

	// Parse server and peer identity
	if err = c.serverEntityAddr.UnmarshalBinary(serverHandshake); err != nil {
		return err
	}
	serverHandshake = serverHandshake[c.serverEntityAddr.Size():]
	serverClientAddr := &EntityAddr{}
	if err = serverClientAddr.UnmarshalBinary(serverHandshake); err != nil {
		return err
	}
	log.Printf("parse identity: server=%+v client=%+v", c.serverEntityAddr, serverClientAddr)

	// Send client handshake
	c.clientEntityAddr.Type = 0 // always use the default socket address type
	if c.nonce == 0 {
		c.setNonce()
	}
	c.clientEntityAddr.Nonce = c.nonce
	local := c.localAddr
	if local.IP.To4() != nil { // use IPv4 address
		c.clientEntityAddr.Address = NewSockAddr(local.IP, local.Port)
	} else { // use IPv6 address
		c.clientEntityAddr.Address = NewSockAddr6(local.IP, local.Port)
	}
	var b bytes.Buffer
	if _, err = b.Write([]byte(BANNER_STR)); err != nil {
		return err
	}
	client, err := c.clientEntityAddr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err = b.Write(client); err != nil {
		return err
	}
	if _, err = c.Write(b.Bytes()); err != nil {
		return err
	}
	log.Printf("send client handshake success: %+v, size=%d", c.clientEntityAddr, b.Len())

	c.globalSeq = atomic.AddUint32(&globalSequence, 1)
	for {
		// Client send negotiation message to server.
		c.negotiation = &NegotiationType{
			Features:        DEFAULT_FEATURES,
			HostType:        uint32(ENTITY_CLIENT),
			GlobalSequence:  c.globalSeq,
			ConnectSequence: c.connectSeq,
			ProtoVersion:    c.connectEntity,
			Flag:            DEFAULT_FLAGS,
		}
		data, err := c.negotiation.MarshalBinary()
		if err != nil {
			return err
		}
		if _, err = c.Write(data); err != nil {
			return err
		}
		log.Printf("send client negotiation success: %+v, size=%d", c.negotiation, len(data))

		// Check negotiation reply message from server.
		c.negotiationReply = &NegotiationReplyType{}
		buf := make([]byte, c.negotiationReply.Size())
		if _, err = c.Read(buf); err != nil {
			return err
		}
		if err = c.negotiationReply.UnmarshalBinary(buf); err != nil {
			return err
		}
		log.Printf("recv server negotiation reply success: %+v", c.negotiationReply)
		log.Printf("got reply tag: %d", c.negotiationReply.Tag)

		switch c.negotiationReply.Tag {
		case MSG_TAG_FEATURES:
			err = fmt.Errorf("protocol feature mismatch")
			return err
		case MSG_TAG_BADPROTOVER:
			err = fmt.Errorf("protocol version mismatch")
			return err
		case MSG_TAG_BADAUTHORIZER:
			err = fmt.Errorf("got BADAUTHORIZER tag")
			return err
		case MSG_TAG_RESETSESSION:
			c.connectSeq = 0
			log.Printf("got RESETSESSION tag, set connect sequence 0")
			continue
		case MSG_TAG_RETRY_GLOBAL:
			if c.negotiationReply.GlobalSequence > c.globalSeq {
				c.globalSeq = c.negotiationReply.GlobalSequence
			}
			c.globalSeq += 1
			log.Printf("got RETRY_GLOBAL tag, current=%d, new=%d",
				c.negotiation.GlobalSequence, c.globalSeq)
			continue
		case MSG_TAG_RETRY_SESSION:
			log.Printf("got RETRY_SESSION, local seq=%d, remote seq=%d",
				c.globalSeq, c.negotiation.GlobalSequence)
			c.connectSeq = c.negotiationReply.ConnectSequence
			continue
		case MSG_TAG_WAIT:
			err = fmt.Errorf("got WAIT tag")
			return err
		case MSG_TAG_SEQ, MSG_TAG_READY:
			log.Printf("server features: 0x%x", c.negotiationReply.Features)
			if c.negotiationReply.Tag == MSG_TAG_SEQ {
				ackSeqBuf := make([]byte, 8)
				if _, err = c.Read(ackSeqBuf); err != nil {
					return err
				}
				var newAckSeq uint64
				binary.Read(bytes.NewBuffer(ackSeqBuf), binary.LittleEndian, &newAckSeq)
				log.Printf("got new ack seq: %d", newAckSeq)
				b.Reset()
				binary.Write(&b, binary.LittleEndian, c.inSeq)
				if _, err = c.Write(b.Bytes()); err != nil {
					return err
				}
				log.Printf("write in seq: %d", newAckSeq)
			}
			c.connectSeq += 1
			if c.negotiationReply.ConnectSequence != c.connectSeq {
				panic("connect sequence not match")
			}
		}
		break
	}
	c.lock.Lock()
	c.state = radosConnStateAuthenticating
	c.lock.Unlock()

	c.wg.Add(2)
	log.Print("start writer to process data from local side")
	go c.writer()
	log.Print("start reader to process data from remote side")
	go c.reader()
	return c.authenticate(prepare)
}

// MonCommand send the command to the RADOS monitor.
func (c *radosConn) MonCommand(cmd []byte) (result []byte, err error) {
	c.moncmdLock.Lock()
	defer c.moncmdLock.Unlock()
	msgCmd := NewMessageMonCommand(c.monmap.FSID)
	msgCmd.AddCmd(cmd)
	if err = msgCmd.Encode(); err != nil {
		log.Printf("encode mon command message failed: %v", err)
		return
	}
	msgCmd.CreateHeader(c.clientEnt, c.getOutSeq(), 0, MSG_PRIO_DEFAULT, 1, 0)
	msgCmd.CreateFooter(MSG_FOOTER_FLAG_LOSSY, 0)
	if err = c.sendMessage(msgCmd); err != nil {
		log.Printf("send auth message failed: %v", err)
		return
	}
	c.cond.Broadcast()

	// Receive the command return message and check the return code.
	var msgCmdReply *MessageMonCommand
	for {
		reply, err := c.recvMessage()
		if err != nil {
			return nil, err
		}
		if realMsg, ok := reply.(*MessageMonCommand); !ok {
			c.recvChan <- reply
			continue
		} else {
			msgCmdReply = realMsg
			break
		}
	}
	if msgCmdReply.RetCode != 0 {
		return nil, fmt.Errorf("mon command return error: code=%d, msg=%s",
			msgCmdReply.RetCode, string(msgCmdReply.ResultMsg))
	}
	return msgCmdReply.Data, nil
}

// authenticate perform the private authority facility with the given keyring.
func (c *radosConn) authenticate(prepare bool) error {
	var (
		ver       uint16 = 1
		transId   uint64
		dataOff   uint16
		signature uint64
	)
	log.Print("start authenticating...")

	// Create the first authenticate message and send to remote server.
	msgAuth, err := NewMessageAuth(AUTH_USER)
	if err != nil {
		log.Printf("create auth message failed: %v", err)
		return err
	}
	if err = msgAuth.Encode(); err != nil {
		log.Printf("encode auth message failed: %v", err)
		return err
	}
	msgAuth.CreateHeader(c.clientEnt, c.getOutSeq(), transId, MSG_PRIO_DEFAULT, ver, dataOff)
	msgAuth.CreateFooter(MSG_FOOTER_FLAG_LOSSY, signature)
	if err := c.sendMessage(msgAuth); err != nil {
		log.Printf("send auth message failed: %v", err)
		return err
	}
	log.Printf("send auth message: seq=%d", msgAuth.Header.Seq)

	// Receive the message from remote server: either auth reply message or monmap message.
	gotMonmap, sentGetSessionKey, sentGetPrincipalKey, finished := false, false, false, false
	for {
		msg, err := c.recvMessage()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *MessageAuthReply:
			switch {
			case !sentGetSessionKey && !sentGetPrincipalKey: // first auth reply
				serverChallenge, err := m.GetServerChallenge()
				if err != nil {
					log.Printf("invalid server challenge: %v", err)
					return err
				}
				log.Printf("server auth challenge: 0x%x", serverChallenge)
				c.serverChallenge = serverChallenge
				c.globalId = m.GlobalId

				// Try to send get-auth-session-key message.
				log.Printf("sending get-auth-session-key message ...")
				sk, err := NewMessageAuthSessionKey(
					m.Protocol, c.serverChallenge, c.clientChallenge, c.cryptoKey)
				if err != nil {
					log.Printf("create get-auth-session-key message failed: %v", err)
					return err
				}
				if err = sk.Encode(); err != nil {
					log.Printf("encode get-auth-session-key message failed: %v", err)
					return err
				}
				sk.CreateHeader(c.clientEnt, c.getOutSeq(), transId, MSG_PRIO_DEFAULT, ver, dataOff)
				sk.CreateFooter(MSG_FOOTER_FLAG_LOSSY, signature)
				if err := c.sendMessage(sk); err != nil {
					log.Printf("send get auth session key message failed: %+v", err)
					return err
				}
				sentGetSessionKey = true
				c.cond.Broadcast()
			case sentGetSessionKey && !sentGetPrincipalKey: // get session key reply
				tickets, err := m.GetSessionTickets(c.cryptoKey)
				if err != nil || len(tickets) == 0 {
					log.Printf("get session key reply failed: %+v", err)
					return err
				}
				c.sessionTicket = tickets[0]
				tpl := "get session key success, use first one\n  serviceId=%d "
				tpl += "validity=%d encrypted=%v secretId=%d\n  sessionKey=%+v"
				log.Printf(tpl, c.sessionTicket.ServiceId, c.sessionTicket.Validity,
					c.sessionTicket.Encrypted, c.sessionTicket.SecretId, c.sessionTicket.SessionKey)
				if prepare {
					return nil
				}

				// Try to send PrincipalKey auth message
				log.Printf("sending get-principal-key message ...")
				pk, err := NewMessageAuthPrincipalKey(m.Protocol, c.globalId, &c.sessionTicket)
				if err != nil {
					log.Printf("create get-auth-principal-session-key message failed: %v", err)
					return err
				}
				if err = pk.Encode(); err != nil {
					log.Printf("encode get-auth-principal-session-key message failed: %v", err)
					return err
				}
				pk.CreateHeader(c.clientEnt, c.getOutSeq(), transId, MSG_PRIO_DEFAULT, ver, dataOff)
				pk.CreateFooter(MSG_FOOTER_FLAG_LOSSY, signature)
				if err := c.sendMessage(pk); err != nil {
					log.Printf("send get-auth-principal-session-key message failed: %v", err)
					return err
				}
				sentGetPrincipalKey = true
				c.cond.Broadcast()
			case sentGetSessionKey && sentGetPrincipalKey: // get principal key reply
				tickets, err := m.GetSessionTickets(&c.sessionTicket.SessionKey)
				if err != nil {
					log.Printf("get auth principal session key failed: %v", err)
					return err
				}
				c.principalTickets = tickets
				tpl := "\n  serviceId=%d validity=%d secretId=%d\n  sessionKey=%+v"
				for i := range tickets {
					log.Printf(tpl, tickets[i].ServiceId, tickets[i].Validity,
						tickets[i].SecretId, tickets[i].SessionKey)
				}
				finished = true
			case !sentGetSessionKey && sentGetPrincipalKey: // invalid state
				err = fmt.Errorf("exchange key failed when doing authenticate")
				log.Print(err)
				return err
			}
		case *MessageMonmap:
			log.Printf("got monmap : epoch=%d, size=%d, count=%d", m.Epoch, m.Size, len(m.Mons))
			c.monmap = &m.monmapType
			gotMonmap = true
		default:
			err = fmt.Errorf("got invalid message when doing authenticate: %v", msg)
			log.Print(err)
			return err
		}
		if gotMonmap && sentGetSessionKey && sentGetPrincipalKey && finished {
			log.Printf("authenticate success: monmap=%+v", c.monmap)
			break
		}
	}
	c.lock.Lock()
	c.state = radosConnStateOpen
	c.lock.Unlock()
	return nil
}

func (c *radosConn) Subscribe(name string) error {
	msgSub := NewMessageMonSubscribe(shortHostname())
	msgSub.Add(name, &subscribeItem{})
	if err := msgSub.Encode(); err != nil {
		log.Printf("encode %s message failed: %v", msgSub.Name(), err)
		return err
	}
	msgSub.CreateHeader(c.clientEnt, c.getOutSeq(), 0, MSG_PRIO_DEFAULT, 3, 0)
	msgSub.CreateFooter(MSG_FOOTER_FLAG_LOSSY, 0)
	if err := c.sendMessage(msgSub); err != nil {
		log.Printf("send %s message failed: %v", msgSub.Name(), err)
		return err
	}
	c.cond.Broadcast()

	// Receive the return message and check the return code.
	for {
		reply, err := c.recvMessage()
		if err != nil {
			return err
		}
		switch realMsg := reply.(type) {
		case *MessageMonmap:
			*c.monmap = realMsg.monmapType
			log.Printf("subscribe monmap success: %+v", realMsg.monmapType)
		default:
			c.recvChan <- reply
			continue
		}
		break
	}
	return nil
}

func (c *radosConn) reader() {
	c.lock.Lock()
	defer func() {
		c.cond.Broadcast()
		c.lock.Unlock()
		log.Printf("reader exit")
		c.wg.Done()
	}()
	tagBuf := make([]byte, 1)
	for c.state != radosConnStateInvalid && c.state != radosConnStateClosed {
		select {
		case <-c.ctx.Done():
			return
		default: // Procss reading data from remote side.
			c.lock.Unlock()
			if _, err := c.Read(tagBuf); err != nil {
				log.Printf("reader read tag failed: %v", err)
				c.lock.Lock()
				c.state = radosConnStateClosed
				continue
			}
			log.Printf("reader got tag: %d", tagBuf[0])
			switch tagBuf[0] {
			case MSG_TAG_ACK:
				log.Print("reader got ACK tag")
				acked := make([]byte, 8)
				if _, err := c.Read(acked); err != nil {
					log.Printf("reader get ack seq failed: %v", err)
					c.lock.Lock()
					c.state = radosConnStateClosed
					break
				}
				c.lock.Lock()
				binary.Read(bytes.NewReader(acked), binary.LittleEndian, &c.outAckedSeq)
				log.Printf("get out acked seq: %d, current out seq: %d", c.outAckedSeq, c.outSeq)
			case MSG_TAG_KEEPALIVE2, MSG_TAG_KEEPALIVE2_ACK:
				log.Print("reader got KEEPALIVE tag")
				c.lock.Lock()
				if err := c.recvKeepAlive(); err != nil {
					log.Printf("reader send keepalive failed: %v", err)
					c.state = radosConnStateClosed
					break
				}
				c.needSendKeepalive = true
				c.cond.Broadcast()
			case MSG_TAG_MSG:
				log.Print("reader got MSG tag")
				c.lock.Lock()
				msg, err := c.readMessage()
				if err != nil {
					log.Printf("reader read msg failed: %v", err)
					continue
				}
				log.Printf("reader read message #%d success", msg.Sequence())
				c.inSeq = msg.Sequence()
				c.cond.Broadcast()
				c.recvChan <- msg
			case MSG_TAG_CLOSE:
				log.Print("reader got CLOSE tag")
				c.lock.Lock()
				c.state = radosConnStateClosed
				break
			default:
				log.Print("reader got bad tag to close the connection")
				c.lock.Lock()
				c.state = radosConnStateClosed
				break
			}
		}
	}
}

func (c *radosConn) writer() {
	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		log.Printf("writer exit")
		c.wg.Done()
	}()
	for c.state != radosConnStateInvalid && c.state != radosConnStateClosed {
		select {
		case <-c.ctx.Done():
			return
		default:
			log.Printf("writer begin processing: state=%d", c.state)
			if c.state == radosConnStateConnecting {
				return
			}
			if c.needSendKeepalive {
				if err := c.sendKeepAlive(); err != nil {
					log.Printf("writer do keepalive failed: %v", err)
				}
				c.needSendKeepalive = false
			}
			if c.inSeq > c.inAckedSeq {
				if err := c.writeAck(); err != nil {
					log.Printf("writer write ack %d failed: %v", c.inSeq, err)
					continue
				}
				c.inAckedSeq = c.inSeq
			}

			// Try to get a message and do sending.
			select {
			case msg := <-c.sendChan:
				data, err := msg.MarshalBinary()
				if err != nil {
					log.Printf("writer marshal message failed: %v", err)
					continue
				}
				data = append(data, byte(MSG_TAG_MSG))
				copy(data[1:], data)
				data[0] = byte(MSG_TAG_MSG)
				if _, err := c.Write(data); err != nil {
					log.Printf("writer send message failed: %v", err)
					continue
				}
				log.Printf("send message success seq=%d", msg.Sequence())
			default:
				log.Printf("writer sleeping: state=%d", c.state)
				c.cond.Wait()
			}
		}
	}
}

func (c *radosConn) sendMessage(msg Message) error {
	c.lock.Lock()
	c.cond.Broadcast()
	c.lock.Unlock()
	ctx, _ := context.WithTimeout(c.ctx, c.WriteTimeout)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.sendChan <- msg:
		return nil
	}
}

func (c *radosConn) recvMessage() (Message, error) {
	c.lock.Lock()
	c.cond.Broadcast()
	c.lock.Unlock()
	ctx, _ := context.WithTimeout(c.ctx, c.ReadTimeout)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-c.recvChan:
		return msg, nil
	}
}

func (c *radosConn) readMessage() (Message, error) {
	// Create a dummpy message object to decode the header.
	msg := &message{}
	header := make([]byte, msg.HeaderSize())
	if _, err := c.Read(header); err != nil {
		return nil, err
	}
	if err := msg.DecodeHeader(header); err != nil {
		return nil, err
	}

	// Create the actual message object by type and set header by decoding.
	// Just care about the following messages, and message with new type can be added here to
	// extend the functionality.
	var m Message
	switch msg.Header.Type {
	case MSG_AUTH:
		m = &MessageAuth{}
	case MSG_AUTH_REPLY:
		m = &MessageAuthReply{}
	case MSG_MON_MAP:
		m = &MessageMonmap{}
	case MSG_MON_COMMAND_ACK:
		m = &MessageMonCommand{}
	case MSG_CONFIG:
		m = &MessageMonSubscribe{}
	default:
		return nil, fmt.Errorf("unrecognized message type: header=%+v", msg.Header)
	}
	m.DecodeHeader(header) // checked before, just ignore the error returned.

	// Read and parse the payload, middle and data parts.
	var got uint32 = 0
	size := msg.Header.FrontLen + msg.Header.MiddleLen + msg.Header.DataLen
	buffer := make([]byte, size)
	if msg.Header.FrontLen > 0 {
		if _, err := c.Read(buffer[got:msg.Header.FrontLen]); err != nil {
			return nil, err
		}
		got += msg.Header.FrontLen
	}
	if msg.Header.MiddleLen > 0 {
		if _, err := c.Read(buffer[got : got+msg.Header.MiddleLen]); err != nil {
			return nil, err
		}
		got += msg.Header.MiddleLen
	}
	if msg.Header.DataLen > 0 {
		if _, err := c.Read(buffer[got : got+msg.Header.DataLen]); err != nil {
			return nil, err
		}
		got += msg.Header.DataLen
	}
	if _, err := m.Decode(buffer); err != nil {
		return nil, err
	}

	// Read message footer and decode.
	footer := make([]byte, msg.FooterSize())
	if _, err := c.Read(footer); err != nil {
		return nil, err
	}
	if err := m.DecodeFooter(footer); err != nil {
		return nil, err
	}
	return m, nil
}

// Send the current timestamp to remote server.
func (c *radosConn) sendKeepAlive() error {
	var b bytes.Buffer
	if _, err := b.Write([]byte{byte(MSG_TAG_KEEPALIVE2)}); err != nil {
		return err
	}
	ts := time.Now().UnixNano()
	sec := uint32(ts / 1000000000)
	nano := uint32(ts % 1000000000)
	if err := binary.Write(&b, binary.LittleEndian, sec); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, nano); err != nil {
		return err
	}
	if _, err := c.Write(b.Bytes()); err != nil {
		return err
	}
	return nil
}

// Read the remote server keepalive timestamp.
func (c *radosConn) recvKeepAlive() error {
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err != nil {
		return err
	}
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &c.keepalive.Second); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.keepalive.Nano); err != nil {
		return err
	}
	log.Printf("receive remote keep alive ack: %d.%d", c.keepalive.Second, c.keepalive.Nano)
	return nil
}

func (c *radosConn) writeAck() error {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, uint8(MSG_TAG_ACK)); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, c.inSeq); err != nil {
		return err
	}
	if _, err := c.Write(b.Bytes()); err != nil {
		return err
	}
	return nil
}

// setNonce generates a random number for current connection.
func (c *radosConn) setNonce() { c.nonce = rand.Uint32() }

func (c *radosConn) getOutSeq() uint64 {
	return atomic.AddUint64(&c.outSeq, 1)
}

// SetLocalAddr sets the local address before connect to the rados cluster.
func (c *radosConn) SetLocalAddr(network, addr string) error {
	tcp, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return err
	}
	c.localAddr = tcp
	return nil
}

/// Following methods implement the net.Conn interface.

func (c *radosConn) Close() error {
	c.lock.Lock()
	c.state = radosConnStateClosed
	c.cond.Broadcast()
	err := c.conn.Close()
	c.lock.Unlock()
	c.wg.Wait()
	return err
}

func (c *radosConn) Read(b []byte) (n int, err error) {
	c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	n, err = c.conn.Read(b)
	return n, err
}

func (c *radosConn) Write(b []byte) (n int, err error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	n, err = c.conn.Write(b)
	return n, err
}

func (c *radosConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *radosConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *radosConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *radosConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *radosConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
