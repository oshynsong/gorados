// message_mon_subscribe.go - define the mon subscribe message

package gorados

import (
	"bytes"
	"encoding/binary"
)

const (
	SUBSCRIBE_MONMAP = "monmap"
	SUBSCRIBE_MGRMAP = "mgrmap"
	SUBSCRIBE_OSDMAP = "osdmap"
	SUBSCRIBE_CONFIG = "config"
)

type subscribeItem struct {
	StartTime uint64
	Flags     uint8
}

// MessageMonSubscribe is used to subscribe client to the rados cluster monitor. No need to
// handle subscribtion return message. Decode implements the `config` returned message.
type MessageMonSubscribe struct {
	message

	Hostname string
	What     map[string]subscribeItem
}

func NewMessageMonSubscribe(hn string) *MessageMonSubscribe {
	result := &MessageMonSubscribe{Hostname: hn}
	result.Header.Type = MSG_MON_SUBSCRIBE
	return result
}

func (m *MessageMonSubscribe) Name() string { return "MonSubscribe" }

func (m *MessageMonSubscribe) Add(name string, content *subscribeItem) {
	if m.What == nil {
		m.What = make(map[string]subscribeItem)
	}
	m.What[name] = *content
}

func (m *MessageMonSubscribe) Encode() error {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, uint32(len(m.What))); err != nil {
		return err
	}
	for k := range m.What {
		nameBytes, err := encodeSizeValue(len(k), []byte(k))
		if err != nil {
			return err
		}
		if _, err := b.Write(nameBytes); err != nil {
			return err
		}
		if err := binary.Write(&b, binary.LittleEndian, m.What[k]); err != nil {
			return err
		}
	}
	hostnameBytes, err := encodeSizeValue(len(m.Hostname), []byte(m.Hostname))
	if err != nil {
		return err
	}
	if _, err := b.Write(hostnameBytes); err != nil {
		return err
	}

	// Put the payload to the `Payload` field.
	if m.Payload == nil {
		m.Payload = make([]byte, 0)
	}
	m.Payload = append(m.Payload, b.Bytes()...)

	return nil
}

func (m *MessageMonSubscribe) Decode(input []byte) (int, error) {
	size, data, err := decodeSizeValue(input, 1)
	if err != nil {
		return 0, err
	}
	m.Payload = data
	return size + SIZE_BYTES, nil
}
