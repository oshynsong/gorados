// message_mon_command.go - define the mon command message

package gorados

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MessageMonCommand is used to send command to the rados cluster monitor and parse the result
// returned from the monitor. Client does not need to build command reply message.
type MessageMonCommand struct {
	messagePaxos

	// FSID only used when sending command.
	FSID [16]byte

	// Return status code and string from the monitor.
	RetCode   int32
	ResultMsg []byte

	// Both need when sending command and parse return result.
	Cmds [][]byte
}

func NewMessageMonCommand(fsid [16]byte) *MessageMonCommand {
	result := &MessageMonCommand{
		messagePaxos: messagePaxos{Mon: -1},
		FSID:         fsid,
	}
	result.Header.Type = MSG_MON_COMMAND
	return result
}

func (m *MessageMonCommand) Name() string { return "MonCommand" }

func (m *MessageMonCommand) AddCmd(cmd []byte) {
	if m.Cmds == nil {
		m.Cmds = make([][]byte, 0)
	}
	m.Cmds = append(m.Cmds, cmd)
}

func (m *MessageMonCommand) Encode() error {
	// Encode paxos message payload bytes.
	if err := m.messagePaxos.Encode(); err != nil {
		return err
	}

	// Encode mon command message payload bytes.
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.FSID); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, uint32(len(m.Cmds))); err != nil {
		return err
	}
	for i := range m.Cmds {
		cmdBytes, err := encodeSizeValue(len(m.Cmds[i]), m.Cmds[i])
		if err != nil {
			return err
		}
		if _, err := b.Write(cmdBytes); err != nil {
			return err
		}
	}

	// Put the payload to the `Payload` field.
	if m.Payload == nil {
		m.Payload = make([]byte, 0)
	}
	m.Payload = append(m.Payload, b.Bytes()...)

	return nil
}

func (m *MessageMonCommand) Decode(input []byte) (decoded int, err error) {
	origin := input[:]
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode the mon command result failed: %v", r)
		}
	}()
	if decoded, err = m.messagePaxos.Decode(input); err != nil {
		return
	}
	input = input[decoded:]
	r := bytes.NewReader(input)
	if err = binary.Read(r, binary.LittleEndian, &m.RetCode); err != nil {
		return
	}
	input = input[len(input)-r.Len():]
	resSize, resBytes, err := decodeSizeValue(input, 1)
	if err != nil {
		return
	}
	m.ResultMsg = resBytes
	input = input[SIZE_BYTES+resSize*1:]

	var cmdCount uint32
	r.Reset(input)
	if err = binary.Read(r, binary.LittleEndian, &cmdCount); err != nil {
		return
	}
	m.Cmds = make([][]byte, cmdCount)
	input = input[SIZE_BYTES:]
	for i := uint32(0); i < cmdCount; i += 1 {
		cmdSize, cmdBytes, err := decodeSizeValue(input, 1)
		if err != nil {
			return decoded, err
		}
		m.Cmds[i] = cmdBytes
		input = input[SIZE_BYTES+cmdSize*1:]
	}

	m.Payload = origin[:len(origin)-len(input)]
	m.Data = input
	return len(input), nil
}
