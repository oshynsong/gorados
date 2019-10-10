// message.go - defines the global message data structure of the RADOS cluster

package gorados

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
)

const (
	// Message tag to distinguish different type messages of the RADOS cluster.
	MSG_TAG_READY                = 1
	MSG_TAG_RESETSESSION         = 2
	MSG_TAG_WAIT                 = 3
	MSG_TAG_RETRY_SESSION        = 4
	MSG_TAG_RETRY_GLOBAL         = 5
	MSG_TAG_CLOSE                = 6
	MSG_TAG_MSG                  = 7
	MSG_TAG_ACK                  = 8
	MSG_TAG_KEEPALIVE            = 9
	MSG_TAG_BADPROTOVER          = 10
	MSG_TAG_BADAUTHORIZER        = 11
	MSG_TAG_FEATURES             = 12
	MSG_TAG_SEQ                  = 13
	MSG_TAG_KEEPALIVE2           = 14
	MSG_TAG_KEEPALIVE2_ACK       = 15
	MSG_TAG_CHALLENGE_AUTHORIZER = 16

	// Message types definition.
	MSG_SHUTDOWN              = 1
	MSG_PING                  = 2
	MSG_MON_MAP               = 4
	MSG_MON_GET_MAP           = 5
	MSG_MON_GET_OSDMAP        = 6
	MSG_MON_METADATA          = 7
	MSG_MON_SUBSCRIBE         = 15
	MSG_MON_SUBSCRIBE_ACK     = 16
	MSG_AUTH                  = 17
	MSG_AUTH_REPLY            = 18
	MSG_MON_GET_VERSION       = 19
	MSG_MON_GET_VERSION_REPLY = 20
	MSG_OSD_MAP               = 41
	MSG_OSD_OP                = 42
	MSG_OSD_OPREPLY           = 43
	MSG_WATCH_NOTIFY          = 44
	MSG_FS_MAP                = 45
	MSG_FORWARD               = 46
	MSG_ROUTE                 = 47
	MSG_POOLOP_REPLY          = 48
	MSG_POOLOP                = 49
	MSG_MON_COMMAND           = 50
	MSG_MON_COMMAND_ACK       = 51
	MSG_LOG                   = 52
	MSG_LOGACK                = 53
	MSG_GETPOOLSTATS          = 58
	MSG_GETPOOLSTATSREPLY     = 59
	MSG_MON_GLOBAL_ID         = 60
	MSG_OSD_BACKOFF           = 61
	MSG_CONFIG                = 62
	MSG_GET_CONFIG            = 63
	MSG_NOP                   = 0x607
	MSG_MON_HEALTH_CHECKS     = 0x608
	MSG_MGR_OPEN              = 0x700
	MSG_MGR_CONFIGURE         = 0x701
	MSG_MGR_REPORT            = 0x702
	MSG_MGR_BEACON            = 0x703
	MSG_MGR_MAP               = 0x704
	MSG_MGR_DIGEST            = 0x705
	MSG_MON_MGR_REPORT        = 0x706
	MSG_SERVICE_MAP           = 0x707
	MSG_MGR_CLOSE             = 0x708
)

// MessagePriorityType defines a message processing priority.
type MessagePriorityType uint16

// Only support 4 different message priority.
const (
	MSG_PRIO_LOW     = MessagePriorityType(64)
	MSG_PRIO_DEFAULT = MessagePriorityType(127)
	MSG_PRIO_HIGH    = MessagePriorityType(196)
	MSG_PRIO_HIGHEST = MessagePriorityType(255)
)

// Pre-defined message utility constants.
const (
	ENCODING_TAG          = 0x01
	MSG_FOOTER_FLAG_LOSSY = 0x01
)

// Message defines the common interface a message should implement.
type Message interface {
	encoding.BinaryMarshaler

	// Getter and setter for a message fields.
	Name() string
	Sequence() uint64
	HeaderSize() int
	FooterSize() int

	// Methods to build a message header, payload, middld, data and footer.
	Encode() error
	CreateHeader(src EntityName, seq, tid uint64, prio MessagePriorityType, ver, dataOff uint16)
	CreateFooter(flag uint8, sig uint64)

	// Methods to parse raw bytes to message header, payload, middld, data and footer.
	DecodeHeader([]byte) error
	Decode([]byte) (int, error)
	DecodeFooter([]byte) error
}

type message struct {
	Header struct {
		Seq           uint64              // message seq# for this message
		Tid           uint64              // transaction id
		Type          uint16              // message type
		Priority      MessagePriorityType // priority: higher value == higher priority
		Version       uint16              // version of message encoding
		FrontLen      uint32              // bytes in main payload
		MiddleLen     uint32              // bytes in middle payload
		DataLen       uint32              // bytes of data payload
		DataOff       uint16              // sender: include full offset
		Entity        EntityName          // the message sender entity
		CompatVersion uint16              // compatible version
		Reserved      uint16              // reserved not used
		Crc           uint32              // header crc32c
	}
	Footer struct {
		FrontCrc  uint32 // front crc32c
		MiddleCrc uint32 // middle crc32c
		DataCrc   uint32 // data crc32c
		Signature uint64 // digital signature for the message
		Flags     uint8  // footer special flags
	}
	Payload []byte
	Middle  []byte
	Data    []byte
}

func (m *message) Name() string     { return "" }
func (m *message) Sequence() uint64 { return m.Header.Seq }
func (m *message) HeaderSize() int  { return binary.Size(m.Header) }
func (m *message) FooterSize() int  { return binary.Size(m.Footer) }

// Encode specify how to build the message exclude the header and footer. Real message should always
// redefine this method to set the payload, middle and data of the message.
func (m *message) Encode() error { return nil }

// CreateHeader creates the message header. It must be called after the message has been encoded.
func (m *message) CreateHeader(src EntityName, seq, tid uint64, prio MessagePriorityType,
	ver, dataOff uint16) {
	m.Header.Seq = seq
	m.Header.Tid = tid
	m.Header.Priority = prio // 4 different priority
	m.Header.Version = ver
	m.Header.FrontLen = uint32(len(m.Payload))
	m.Header.MiddleLen = uint32(len(m.Middle))
	m.Header.DataLen = uint32(len(m.Data))
	m.Header.DataOff = dataOff
	m.Header.Entity = src
	m.Header.CompatVersion = 1 // set fixed value 1

	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.Header); err != nil {
		panic(err)
	}
	header := b.Bytes()
	m.Header.Crc = calculateCrc32(header[:len(header)-4])
}

// CreateFooter creates the message footer. It must be called after the message has been encoded.
func (m *message) CreateFooter(flag uint8, sig uint64) {
	m.Footer.FrontCrc = calculateCrc32(m.Payload)
	m.Footer.MiddleCrc = calculateCrc32(m.Middle)
	m.Footer.DataCrc = calculateCrc32(m.Data)
	m.Footer.Signature = sig
	m.Footer.Flags = flag
}

// MarshalBinary encodes the built message to little endian raw bytes, which are ready to send with
// low-level socket or connection. The message shouldn't be modified after calling this method.
func (m *message) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.Header); err != nil {
		return nil, err
	}
	if m.Payload != nil && len(m.Payload) != 0 {
		if err := binary.Write(&b, binary.LittleEndian, m.Payload); err != nil {
			return nil, err
		}
	}
	if m.Middle != nil && len(m.Middle) != 0 {
		if err := binary.Write(&b, binary.LittleEndian, m.Middle); err != nil {
			return nil, err
		}
	}
	if m.Data != nil && len(m.Data) != 0 {
		if err := binary.Write(&b, binary.LittleEndian, m.Data); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&b, binary.LittleEndian, m.Footer); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// DecodeHeader decode the header field from raws bytes and check the header crc32.
func (m *message) DecodeHeader(input []byte) error {
	buf := bytes.NewBuffer(input)
	if err := binary.Read(buf, binary.LittleEndian, &m.Header); err != nil {
		return err
	}

	headerCrc := calculateCrc32(input[:m.HeaderSize()-4])
	if m.Header.Crc != headerCrc {
		return fmt.Errorf("header crc32 not match: actual %#x, got %#x", headerCrc, m.Header.Crc)
	}

	return nil
}

// DecodeFooter decode the footer field from raw bytes and check the crc32 for payload/middle/data.
// The payload/middle/data must be got before calling this method.
func (m *message) DecodeFooter(input []byte) error {
	buf := bytes.NewBuffer(input)
	if err := binary.Read(buf, binary.LittleEndian, &m.Footer); err != nil {
		return err
	}

	frontCrc := calculateCrc32(m.Payload)
	if m.Footer.FrontCrc != frontCrc {
		return fmt.Errorf(
			"front crc32 not match: actual 0x%x, got 0x%x", frontCrc, m.Footer.FrontCrc)
	}

	middleCrc := calculateCrc32(m.Middle)
	if m.Footer.MiddleCrc != middleCrc {
		return fmt.Errorf(
			"middle crc32 not match: actual 0x%x, got 0x%x", middleCrc, m.Footer.MiddleCrc)
	}

	dataCrc := calculateCrc32(m.Data)
	if m.Footer.DataCrc != dataCrc {
		return fmt.Errorf(
			"data crc32 not match: actual 0x%x, got 0x%x", dataCrc, m.Footer.DataCrc)
	}

	return nil
}

// Decode specify how to parse the raw bytes as the payload/middle/data for current message. Real
// message should always redefine this method.
func (m *message) Decode(input []byte) (decoded int, err error) { return }

// messagePaxos wraps the global message and defines the common message data structure to
// connect to the monitor node. User should not create and use this message directly.
type messagePaxos struct {
	message

	Version    uint64
	Mon        int16 // must be -1 for compatiblity.
	MonTransId uint64
}

func (m *messagePaxos) Encode() error {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.Version); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, m.Mon); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, m.MonTransId); err != nil {
		return err
	}

	// Put the payload bytes to the `Payload` field.
	if m.Payload == nil {
		m.Payload = make([]byte, 0)
	}
	m.Payload = append(m.Payload, b.Bytes()...)
	return nil
}

func (m *messagePaxos) Decode(input []byte) (int, error) {
	buf := bytes.NewBuffer(input)
	if err := binary.Read(buf, binary.LittleEndian, &m.Version); err != nil {
		return 0, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &m.Mon); err != nil {
		return 0, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &m.MonTransId); err != nil {
		return 0, err
	}
	return binary.Size(m.Version) + binary.Size(m.Mon) + binary.Size(m.MonTransId), nil
}
