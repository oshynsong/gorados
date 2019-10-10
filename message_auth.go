// message_auth.go - define the auth message to connect to monitor

package gorados

import (
	"bytes"
	"encoding/binary"
	"math/rand"
)

const (
	AUTH_AES_IV    = "cephsageyudagreg"
	AUTH_USER      = "admin"
	AUTH_PROTOCOL  = 0x02 // CEPHX protocol
	AUTH_ENC_MAGIC = 0xff009cad8826aa55

	// Authenticate request types of the CEPHX protocol.
	CEPHX_GET_AUTH_SESSION_KEY      = 0x0100
	CEPHX_GET_PRINCIPAL_SESSION_KEY = 0x0200
	CEPHX_GET_ROTATING_KEY          = 0x0400
)

// MessageAuth is used to connect to the rados cluster monitor node for authentication.
// Only implements the CEPHX auth protocol with the following steps:
//           [client]                                  [server]
// 1. send auth message              -------->  supported auth methods
//    got server challenge           <--------  return auth reply
// 2. send get-session-key message   -------->  client challange, encrypted with keyring
//    got session tickets            <--------  check crypted key, create session tickets
// 3. send get-principal-key message -------->  check the content with session key
//    got principal tickets          <--------  send principal 3 tickets
type MessageAuth struct {
	messagePaxos

	Protocol    uint32
	AuthData    []byte
	MonmapEpoch uint32
	authType    uint16
}

func NewMessageAuth(authUser string) (*MessageAuth, error) {
	auth := struct {
		EncVersion uint8
		Supported  []uint32
		EntityType uint32
		EntityId   []byte
		GlobalId   uint64
	}{
		EncVersion: 0x01,
		Supported:  []uint32{AUTH_PROTOCOL},
		EntityType: uint32(ENTITY_CLIENT),
	}

	// Encode the authorization user entity id: uint32(size) + string value.
	if len(authUser) == 0 {
		authUser = AUTH_USER
	}
	if entityId, err := encodeSizeValue(len(authUser), []byte(authUser)); err != nil {
		return nil, err
	} else {
		auth.EntityId = entityId
	}

	// Encode the whole authorization data bytes in the field `AuthData`. (34 bytes default)
	// Format: size(4 bytes) + encode version(1 byte) +
	//         supported protocols count(4 bytes) + supported protocol(4 byte){1...n} +
	//         entity type(4 bytes) + entity id(size(4 bytes) + value) + global id(8 bytes)
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, auth.EncVersion); err != nil {
		return nil, err
	}
	if supportedProto, err := encodeSizeValue(len(auth.Supported), auth.Supported); err != nil {
		return nil, err
	} else {
		buf.Write(supportedProto)
	}
	if err := binary.Write(&buf, binary.LittleEndian, auth.EntityType); err != nil {
		return nil, err
	}
	if _, err := buf.Write(auth.EntityId); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, auth.GlobalId); err != nil {
		return nil, err
	}
	authData, err := encodeSizeValue(buf.Len(), buf.Bytes())
	if err != nil {
		return nil, err
	}

	// Build message auth object and fill the payload.
	result := &MessageAuth{
		messagePaxos: messagePaxos{Mon: -1},
		AuthData:     authData,
	}
	result.Header.Type = MSG_AUTH
	return result, nil
}

func NewMessageAuthSessionKey(authProto uint32, server, client uint64,
	cryptoKey *CryptoKey) (result *MessageAuth, err error) {
	// Build the get-auth-session request.
	req := struct {
		Type      uint16
		EncTag    uint8
		Challenge uint64
		Key       uint64

		// The ticket for this request
		TicketEncTag uint8
		SecretId     uint64
		TicketBlob   []byte
	}{}
	req.Type = CEPHX_GET_AUTH_SESSION_KEY
	req.EncTag = ENCODING_TAG
	req.Challenge = client
	req.Key, err = cryptChallange(req.Challenge, server, cryptoKey)
	if err != nil {
		return nil, err
	}
	req.TicketEncTag = ENCODING_TAG

	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.LittleEndian, req.Type); err != nil {
		return nil, err
	}
	if err = binary.Write(&buf, binary.LittleEndian, req.EncTag); err != nil {
		return nil, err
	}
	if err = binary.Write(&buf, binary.LittleEndian, req.Challenge); err != nil {
		return nil, err
	}
	if err = binary.Write(&buf, binary.LittleEndian, req.Key); err != nil {
		return nil, err
	}
	if err = binary.Write(&buf, binary.LittleEndian, req.TicketEncTag); err != nil {
		return nil, err
	}
	if err = binary.Write(&buf, binary.LittleEndian, req.SecretId); err != nil {
		return nil, err
	}
	ticketBytes, err := encodeSizeValue(len(req.TicketBlob), req.TicketBlob)
	if err != nil {
		return nil, err
	}
	if _, err = buf.Write(ticketBytes); err != nil {
		return nil, err
	}

	bufBytes := buf.Bytes()
	authDataBytes, err := encodeSizeValue(len(bufBytes), bufBytes)
	if err != nil {
		return nil, err
	}
	result = &MessageAuth{
		messagePaxos: messagePaxos{Mon: -1},
		Protocol:     authProto,
		AuthData:     authDataBytes,
		authType:     req.Type,
	}
	result.Header.Type = MSG_AUTH
	return result, nil
}

func NewMessageAuthPrincipalKey(authProto uint32, globalId uint64,
	ticket *authSessionTicket) (result *MessageAuth, err error) {
	var (
		buf     bytes.Buffer
		encTag  uint8  = ENCODING_TAG
		reqType uint16 = CEPHX_GET_PRINCIPAL_SESSION_KEY
		keys    uint32 = 0x15 // [TODO] build the ticket manager facility.
	)

	// Build the auth data of each field defined by the protocol.
	if err = binary.Write(&buf, binary.LittleEndian, reqType); err != nil { // 4 bytes
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, encTag); err != nil { // 1 byte
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, globalId); err != nil { // 8 bytes
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, ticket.ServiceId); err != nil { // 4 bytes
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, encTag); err != nil { // 1 bytes
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, ticket.SecretId); err != nil { // 8 bytes
		return
	}
	blob, err := encodeSizeValue(len(ticket.Blob), ticket.Blob)
	if err != nil {
		return
	}
	if _, err = buf.Write(blob); err != nil {
		return
	}

	// Build the authorizer data.
	var authMsg bytes.Buffer
	nonce := rand.Uint64()
	if err = binary.Write(&authMsg, binary.LittleEndian, uint8(2)); err != nil { // 8 bytes
		return
	}
	if err = binary.Write(&authMsg, binary.LittleEndian, nonce); err != nil { // 8 bytes
		return
	}
	if err = binary.Write(&authMsg, binary.LittleEndian, false); err != nil { // 8 bytes
		return
	}
	if err = binary.Write(&authMsg, binary.LittleEndian, uint64(0)); err != nil { // 8 bytes
		return
	}
	encBytes, err := encodeEncrypt(authMsg.Bytes(), &ticket.SessionKey)
	if err != nil {
		return
	}
	if _, err = buf.Write(encBytes); err != nil {
		return
	}

	if err = binary.Write(&buf, binary.LittleEndian, encTag); err != nil { // 1 bytes
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, keys); err != nil { // 4 bytes
		return
	}

	// Encode the total auth data with prefix size and build the auth message.
	bufBytes := buf.Bytes()
	authDataBytes, err := encodeSizeValue(len(bufBytes), bufBytes)
	if err != nil {
		return nil, err
	}
	result = &MessageAuth{
		messagePaxos: messagePaxos{Mon: -1},
		Protocol:     authProto,
		AuthData:     authDataBytes,
		authType:     reqType,
	}
	result.Header.Type = MSG_AUTH
	return result, nil
}

func (m *MessageAuth) Name() string { return "Auth" }

func (m *MessageAuth) Encode() error {
	// Encode paxos message payload bytes.
	if err := m.messagePaxos.Encode(); err != nil {
		return err
	}

	// Encode auth message payload bytes.
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.Protocol); err != nil {
		return err
	}
	if _, err := b.Write(m.AuthData); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, m.MonmapEpoch); err != nil {
		return err
	}

	// Put the auth payload to the `Payload` field.
	if m.Payload == nil {
		m.Payload = make([]byte, 0)
	}
	m.Payload = append(m.Payload, b.Bytes()...)

	return nil
}

func (m *MessageAuth) Decode(input []byte) (int, error) {
	size, err := m.messagePaxos.Decode(input)
	if err != nil {
		return 0, err
	}

	protoSize := binary.Size(m.Protocol)
	buf := bytes.NewBuffer(input[size : size+protoSize])
	if err := binary.Read(buf, binary.LittleEndian, &m.Protocol); err != nil {
		return protoSize, err
	}

	epochSize := binary.Size(m.MonmapEpoch)
	buf = bytes.NewBuffer(input[len(input)-epochSize:])
	if err := binary.Read(buf, binary.LittleEndian, &m.MonmapEpoch); err != nil {
		return protoSize, err
	}
	m.AuthData = input[size+protoSize : len(input)-epochSize : len(input)-epochSize]

	m.Payload = input
	return len(input), nil
}

func cryptChallange(client, server uint64, secret *CryptoKey) (res uint64, err error) {
	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.LittleEndian, server); err != nil {
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, client); err != nil {
		return
	}
	encBytes, err := encodeEncrypt(buf.Bytes(), secret)
	if err != nil {
		return
	}

	// Transform the crypted bytes to an uint64 number.
	var tmp uint64
	size := binary.Size(res)
	reader := bytes.NewReader(encBytes)
	for i := 0; i+size <= len(encBytes); i += size {
		if err = binary.Read(reader, binary.LittleEndian, &tmp); err != nil {
			return
		}
		res ^= tmp
	}
	return res, nil
}

func encodeEncrypt(data interface{}, secret *CryptoKey) ([]byte, error) {
	var (
		tag   uint8  = ENCODING_TAG
		magic uint64 = AUTH_ENC_MAGIC
		buf   bytes.Buffer
	)
	if err := binary.Write(&buf, binary.LittleEndian, tag); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, magic); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, data); err != nil {
		return nil, err
	}

	// Use the crypto key to encrypt the data: tag, magic and data.
	cryptedBytes, err := secret.Encrypt(buf.Bytes())
	if err != nil {
		return nil, err
	}

	// Encode the encrypted bytes with prefixed size.
	encBytes, err := encodeSizeValue(len(cryptedBytes), cryptedBytes)
	if err != nil {
		return nil, err
	}
	return encBytes, nil
}
