// protocol.go - defines the private protocol of the RADOS cluster

package gorados

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	BANNER_STR  = "ceph v027"
	BANNER_SIZE = 9

	AF_INET   = 2
	AF_INET6  = 10
	ADDR_SIZE = 128

	// Client constants for the RADOS private protocol which use following default value.
	DEFAULT_FEATURES = 0x3ffddff8ffacfffb
	DEFAULT_FLAGS    = 0x01 // policy.lossy
)

type ConnectEntity uint32

const (
	// The remote entity to connect which is specified by the protocol version.
	MON ConnectEntity = 0x0f // mon protocol version to specify the mon entity
	OSD ConnectEntity = 0x18 // osd protocol version to specify the osd entity
)

// EntityType specify the entity type in the RADOS cluster.
type EntityType uint8

const (
	ENTITY_MON    EntityType = 0x01
	ENTITY_MDS    EntityType = 0x02
	ENTITY_OSD    EntityType = 0x04
	ENTITY_CLIENT EntityType = 0x08
	ENTITY_MGR    EntityType = 0x10
	ENTITY_AUTH   EntityType = 0x20
	ENTITY_ANY    EntityType = 0xFF
)

// EntityName specify an entity with a specified type and number in the RADOS cluster.
type EntityName struct {
	Type EntityType
	Num  int64
}

func (e EntityName) String() string {
	var name string
	switch e.Type {
	case ENTITY_MON:
		name = "mon"
	case ENTITY_MDS:
		name = "mds"
	case ENTITY_MGR:
		name = "mgr"
	case ENTITY_OSD:
		name = "osd"
	case ENTITY_CLIENT:
		name = "client"
	case ENTITY_AUTH:
		name = "auth"
	case ENTITY_ANY:
		fallthrough
	default:
		name = "?"
	}
	return fmt.Sprintf("%s.%d", name, e.Num)
}

// SockAddr defines a operating system socket addr for IPv4. It implements encoding.BinaryMarshaler
// and encoding.BinaryUnmarshaler interfaces. The marshal operation formats to fixed 128 bytes.
type SockAddr struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
}

// NewSockAddr create the socket address object for IPv4.
func NewSockAddr(ip net.IP, port int) *SockAddr {
	if ip.To4() == nil {
		return nil
	}
	var address [4]byte
	for i, b := range ip.To4() {
		address[i] = b
	}
	return &SockAddr{
		Family: AF_INET,
		Port:   uint16(port),
		Addr:   address,
	}
}

func (s *SockAddr) Size() int { return ADDR_SIZE }

func (s *SockAddr) AddrIP() net.IP { return net.IP(s.Addr[:]) }

func (s *SockAddr) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, s.Size())
	b := bytes.NewBuffer(buf)
	if err := binary.Write(b, binary.BigEndian, s); err != nil {
		return nil, err
	}
	pad := make([]byte, s.Size()-8)
	if _, err := b.Write(pad); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *SockAddr) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	if err := binary.Read(b, binary.BigEndian, s); err != nil {
		return err
	}
	s.Family = (s.Family >> 8) + ((s.Family & 0xff) << 8)
	return nil
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("family=%d,port=%d,addr=%s", s.Family, s.Port, s.AddrIP())
}

// SockAddr6 defines a operating system socket addr for IPv6. It implements encoding.BinaryMarshaler
// and encoding.BinaryUnmarshaler interfaces. The marshal operation format to fixed 128 bytes.
type SockAddr6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     [16]byte
	ScopeId  uint32
}

// NewSockAddr6 create the socket address object for IPv6, the last info params is the flowInfo
// for the IPv6 address which is optional. Scope id will be parsed automatically.
func NewSockAddr6(ip net.IP, port int, info ...uint32) *SockAddr6 {
	if ip.To16() == nil {
		return nil
	}
	var address [16]byte
	for i, b := range ip.To16() {
		address[i] = b
	}
	result := &SockAddr6{
		Family: AF_INET6,
		Port:   uint16(port),
		Addr:   address,
	}
	if len(info) == 1 {
		result.FlowInfo = info[0]
	}
	// Parse scope id based on the multicast address
	if address[0] == 0xff { // multicast address: ff0s::/8
		result.ScopeId = uint32(address[1])
	}
	return result
}

func (s *SockAddr6) Size() int { return ADDR_SIZE }

func (s *SockAddr6) AddrIP() net.IP { return net.IP(s.Addr[:]) }

func (s *SockAddr6) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, s.Size())
	b := bytes.NewBuffer(buf)
	if err := binary.Write(b, binary.BigEndian, s); err != nil {
		return nil, err
	}
	pad := make([]byte, s.Size()-28)
	if _, err := b.Write(pad); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *SockAddr6) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	if err := binary.Read(b, binary.BigEndian, s); err != nil {
		return err
	}
	return nil
}

func (s *SockAddr6) String() string {
	return fmt.Sprintf("family=%d,port=%d,flowinfo=%x,addr=%s,scopeid=%d",
		s.Family, s.Port, s.FlowInfo, s.AddrIP(), s.ScopeId)
}

// EntityAddr holds the identity for each entity in the network communication. It implements the
// encoding.BinaryMarshaler and encoding.BinaryUnmarshaler interfaces to encode and decode.
type EntityAddr struct {
	Type    uint32
	Nonce   uint32
	Address interface{}
}

func (e *EntityAddr) Size() int { return 4 + 4 + ADDR_SIZE }

func (e *EntityAddr) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, e.Size())
	b := bytes.NewBuffer(buf)
	if err := binary.Write(b, binary.LittleEndian, e.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(b, binary.LittleEndian, e.Nonce); err != nil {
		return nil, err
	}
	if err := binary.Write(b, binary.BigEndian, e.Address); err != nil {
		return nil, err
	}
	addrSize := binary.Size(e.Address)
	pad := make([]byte, ADDR_SIZE-addrSize)
	if _, err := b.Write(pad); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (e *EntityAddr) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	if err := binary.Read(b, binary.LittleEndian, &e.Type); err != nil {
		return err
	}
	if err := binary.Read(b, binary.LittleEndian, &e.Nonce); err != nil {
		return err
	}

	var family uint16
	if err := binary.Read(b, binary.BigEndian, &family); err != nil {
		return err
	}
	var address interface{}
	switch family {
	case AF_INET:
		address = &SockAddr{}
	case AF_INET6:
		address = &SockAddr6{}
	default:
		e.Address = data[8:e.Size()]
		return nil
	}

	b = bytes.NewReader(data[8:e.Size()])
	if err := binary.Read(b, binary.BigEndian, address); err != nil {
		return err
	}
	e.Address = address
	return nil
}

// NegotiationType defines the client to server negotiation message.
type NegotiationType struct {
	Features        uint64
	HostType        uint32
	GlobalSequence  uint32
	ConnectSequence uint32
	ProtoVersion    uint32
	AuthorizerProto uint32
	AuthorizerSize  uint32
	Flag            uint8
}

func (n *NegotiationType) Size() int { return binary.Size(n) }

func (n *NegotiationType) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, n); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (n *NegotiationType) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	return binary.Read(b, binary.LittleEndian, n)
}

// NegotiationType defines the server to client negotiation reply message.
type NegotiationReplyType struct {
	Tag             uint8
	Features        uint64
	GlobalSequence  uint32
	ConnectSequence uint32
	ProtoVersion    uint32
	AuthorizerSize  uint32
	Flag            uint8
}

func (n *NegotiationReplyType) Size() int { return binary.Size(n) }

func (n *NegotiationReplyType) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, n); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (n *NegotiationReplyType) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	return binary.Read(b, binary.LittleEndian, n)
}

// Time is the timestamp value used in the message.
type Time struct {
	Second uint32
	Nano   uint32
}

// CryptoKey is the secret key to crypt when connecting the rados cluster.
// structure: type(uint16) + created(uint64) + length(uint16) + rand(16bytes)
type CryptoKey struct {
	Type    uint16
	Created struct {
		Second uint32
		Nano   uint32
	}
	Random []byte
}

func (k *CryptoKey) EncodeLen() int {
	return binary.Size(k.Type) + binary.Size(k.Created) + 2 + len(k.Random)
}

func (k *CryptoKey) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, k.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, k.Created); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, uint16(len(k.Random))); err != nil {
		return nil, err
	}
	if _, err := b.Write(k.Random); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (k *CryptoKey) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &k.Type); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &k.Created); err != nil {
		return err
	}
	var length uint16
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	decoded := len(data) - reader.Len()
	k.Random = make([]byte, length)
	copy(k.Random, data[decoded:])
	return nil
}

func (k *CryptoKey) Encrypt(data []byte) ([]byte, error) {
	return aesEncrypt(k.Random, data, []byte(AUTH_AES_IV))
}

func (k *CryptoKey) Decrypt(data []byte) ([]byte, error) {
	return aesDecrypt(k.Random, data, []byte(AUTH_AES_IV))
}
