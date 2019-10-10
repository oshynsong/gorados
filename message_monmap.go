// message_monmap.go - define the monmap message data structure

package gorados

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

type monType struct {
	Name string // encode format: size(4 bytes) + value
	Tag  uint8
	Pad  uint8
	Type uint8
	Addr interface{} // SockAddr for ipv4 and SockAddr6 for ipv6
}

type monmapType struct {
	EncodingVersion uint8
	MinCompatible   uint8
	Size            uint32
	FSID            [16]byte
	Epoch           uint32
	Mons            []monType // encode format: length(4 bytes) + value
	LastChanged     Time
	Created         Time
}

// MessageMonmap is sent by the remote monitor to client to know about all monitors.
type MessageMonmap struct {
	message
	monmapType
}

func (m *MessageMonmap) Name() string { return "Monmap" }

func (m *MessageMonmap) Decode(input []byte) (int, error) {
	m.Payload = input[:]

	var decoded int
	buf := bytes.NewReader(input)

	// First 4 bytes is the size of the monmap.
	var size uint32
	if err := binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return decoded, err
	}
	if len(input) < int(4+size) {
		return decoded, fmt.Errorf("invalid monmap message")
	}
	decoded += SIZE_BYTES

	// Decode the monmap fields.
	if err := binary.Read(buf, binary.LittleEndian, &m.EncodingVersion); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.EncodingVersion)

	if err := binary.Read(buf, binary.LittleEndian, &m.MinCompatible); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.MinCompatible)

	if err := binary.Read(buf, binary.LittleEndian, &m.Size); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.Size)

	if err := binary.Read(buf, binary.LittleEndian, &m.FSID); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.FSID)

	if err := binary.Read(buf, binary.LittleEndian, &m.Epoch); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.Epoch)

	// Mon array: size(4 bytes) + monType{1...n}
	if err := binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return decoded, err
	}
	decoded += SIZE_BYTES
	input = input[decoded:]
	m.Mons = make([]monType, size)
	for i := range m.Mons {
		n, data, err := decodeSizeValue(input, 1)
		if err != nil {
			return decoded, err
		}
		m.Mons[i].Name = string(data)
		decoded += SIZE_BYTES + n
		input = input[SIZE_BYTES+n:]

		buf = bytes.NewReader(input)
		if err := binary.Read(buf, binary.LittleEndian, &m.Mons[i].Tag); err != nil {
			return decoded, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &m.Mons[i].Pad); err != nil {
			return decoded, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &m.Mons[i].Type); err != nil {
			return decoded, err
		}
		n = binary.Size(m.Mons[i].Tag) + binary.Size(m.Mons[i].Pad) + binary.Size(m.Mons[i].Type)
		decoded += n
		input = input[n:]

		n, data, err = decodeSizeValue(input, 1)
		if err != nil {
			return decoded, err
		}

		// Parse the public network address of the monitor.
		var typ, nonce uint32
		buf.Reset(data)
		if err := binary.Read(buf, binary.LittleEndian, &typ); err != nil {
			return decoded, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &nonce); err != nil {
			return decoded, err
		}
		data = data[binary.Size(typ)+binary.Size(nonce):]
		addrLen, addr, err := decodeSizeValue(data, 1)
		if addrLen == 16 { // 16 bytes sockaddr_in for ipv4
			realAddr := &SockAddr{}
			if err = realAddr.UnmarshalBinary(addr); err != nil {
				log.Printf("parse public network address for monitor %s failed", m.Mons[i].Name)
				m.Mons[i].Addr = addr
			} else {
				m.Mons[i].Addr = realAddr
			}
		} else if addrLen == 28 { // 28 bytes sockaddr_in6 for ipv6
			realAddr := &SockAddr6{}
			if err = realAddr.UnmarshalBinary(addr); err != nil {
				log.Printf("parse public network address for monitor %s failed", m.Mons[i].Name)
				m.Mons[i].Addr = addr
			} else {
				m.Mons[i].Addr = realAddr
			}
		} else {
			log.Printf("parse public network address for monitor %s failed", m.Mons[i].Name)
			m.Mons[i].Addr = addr
		}

		decoded += SIZE_BYTES + n
		input = input[SIZE_BYTES+n:]
	}

	buf.Reset(input)
	if err := binary.Read(buf, binary.LittleEndian, &m.LastChanged); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.LastChanged)

	if err := binary.Read(buf, binary.LittleEndian, &m.Created); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.Created)

	return len(m.Payload), nil
}
