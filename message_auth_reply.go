// message_auth_reply.go - define the auth reply message got from monitor

package gorados

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MessageAuthReply is sent by the remote monitor when connecting to the rados cluster.
type MessageAuthReply struct {
	message

	Protocol uint32
	RetCode  int32
	GlobalId uint64
	Result   []byte
	Message  []byte
}

func NewMessageAuthReply() *MessageAuthReply {
	return &MessageAuthReply{Protocol: AUTH_PROTOCOL}
}

func (m *MessageAuthReply) Name() string { return "AuthReply" }

func (m *MessageAuthReply) Encode() error {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, m.Protocol); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, m.RetCode); err != nil {
		return err
	}
	if err := binary.Write(&b, binary.LittleEndian, m.GlobalId); err != nil {
		return err
	}
	if resultBytes, err := encodeSizeValue(len(m.Result), m.Result); err != nil {
		return err
	} else {
		b.Write(resultBytes)
	}
	if msgBytes, err := encodeSizeValue(len(m.Message), m.Message); err != nil {
		return err
	} else {
		b.Write(msgBytes)
	}

	// Put the payload bytes to the `Payload` field.
	if m.Payload == nil {
		m.Payload = make([]byte, 0)
	}
	m.Payload = append(m.Payload, b.Bytes()...)
	return nil
}

func (m *MessageAuthReply) Decode(input []byte) (int, error) {
	var decoded int

	// Decode the first three fields.
	buf := bytes.NewBuffer(input)
	if err := binary.Read(buf, binary.LittleEndian, &m.Protocol); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.Protocol)
	if err := binary.Read(buf, binary.LittleEndian, &m.RetCode); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.RetCode)
	if err := binary.Read(buf, binary.LittleEndian, &m.GlobalId); err != nil {
		return decoded, err
	}
	decoded += binary.Size(m.GlobalId)

	// Decode result field: raw bytes array encode with size and value
	resultLen, resultVal, err := decodeSizeValue(input[decoded:], 1)
	if err != nil {
		return decoded, err
	}
	m.Result = resultVal
	decoded += SIZE_BYTES + resultLen*1

	// Decode the message field: raw bytes array encode with size and value
	msgLen, msgVal, err := decodeSizeValue(input[decoded:], 1)
	if err != nil {
		return decoded, err
	}
	m.Message = msgVal
	decoded += SIZE_BYTES + msgLen*1

	m.Payload = input[:decoded]
	return decoded, nil
}

// GetServerChallenge treat this auth reply message as a server challenge reply and try to
// decode the server challenge value from the `Result` field. Format shows as follows:
//     [tag]1 + [server challenge]8
func (m *MessageAuthReply) GetServerChallenge() (uint64, error) {
	var serverChallenge uint64
	if len(m.Result) != 1+binary.Size(serverChallenge) {
		return 0, fmt.Errorf("invalid server challenge format")
	}
	if m.Result[0] != ENCODING_TAG {
		return 0, fmt.Errorf("invalid server challenge encoding tag: %d", m.Result[0])
	}
	buf := bytes.NewBuffer(m.Result[1:])
	if err := binary.Read(buf, binary.LittleEndian, &serverChallenge); err != nil {
		return 0, nil
	}
	return serverChallenge, nil
}

// authSessionTicket is the ticket for authentication for internal use.
type authSessionTicket struct {
	ServiceId  uint32
	SessionKey CryptoKey
	Validity   uint64
	Encrypted  bool
	SecretId   uint64
	Blob       []byte
}

// GetSessionTickets treat the auth reply message a get-auth-session-key reply and try to
// decode the service ticket returned from the remote server. The format shows as follows:
//    [req type]2 + [status]4 + [tag]1 +
//    [ticket vector length]4 +
//        [service id]4 + [tag]1 + [encrypted service ticket[length]4 + value] +
//        [encrypted]1 + [ticket blob [length]4 + [value [tag]1 + [secretid]8 + [blob]]]
func (m *MessageAuthReply) GetSessionTickets(key *CryptoKey) (res []authSessionTicket, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("get service ticket failed: %v", r)
		}
	}()
	var (
		reqType  uint16
		status   int32
		length   int32
		tagErr   error = fmt.Errorf("check encoding tag failed")
		magicErr error = fmt.Errorf("check auth magic failed")
	)
	r := bytes.NewReader(m.Result)
	if err = binary.Read(r, binary.LittleEndian, &reqType); err != nil {
		return nil, err
	}
	if reqType != CEPHX_GET_AUTH_SESSION_KEY && reqType != CEPHX_GET_PRINCIPAL_SESSION_KEY {
		return nil, fmt.Errorf("invalid request type: %#x", reqType)
	}
	if err = binary.Read(r, binary.LittleEndian, &status); err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("get service ticket failed, return status: %d", status)
	}
	if !checkEncodingTag(r) {
		return nil, tagErr
	}

	// Decode ticket vector length and its value.
	if err = binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, fmt.Errorf("no service ticket")
	}
	tickets := make([]authSessionTicket, length)
	tBytes := m.Result[len(m.Result)-r.Len():]
	for i := int32(0); i < length; i += 1 {
		tReader := bytes.NewReader(tBytes)
		if err := binary.Read(tReader, binary.LittleEndian, &tickets[i].ServiceId); err != nil {
			return nil, err
		}
		if !checkEncodingTag(tReader) {
			return nil, tagErr
		}
		tBytes = tBytes[len(tBytes)-tReader.Len():]

		// Parse the encrypted ticket: [length]4 + [value]
		ticketSize, encryptTicket, err := decodeSizeValue(tBytes, 1)
		if err != nil {
			return nil, err
		}
		tBytes = tBytes[SIZE_BYTES+ticketSize*1:]

		// Decode the ticket value.
		decodeTicketBytes, err := key.Decrypt(encryptTicket)
		if err != nil {
			return nil, err
		}
		tReader.Reset(decodeTicketBytes)
		if !checkEncodingTag(tReader) {
			return nil, tagErr
		}
		if !checkAuthMagic(tReader) {
			return nil, magicErr
		}
		if !checkEncodingTag(tReader) {
			return nil, tagErr
		}
		decodeTicketBytes = decodeTicketBytes[len(decodeTicketBytes)-tReader.Len():]
		if err := tickets[i].SessionKey.UnmarshalBinary(decodeTicketBytes); err != nil {
			return nil, err
		}
		decodeTicketBytes = decodeTicketBytes[tickets[i].SessionKey.EncodeLen():]
		tReader.Reset(decodeTicketBytes)
		if err := binary.Read(tReader, binary.LittleEndian, &tickets[i].Validity); err != nil {
			return nil, err
		}

		// Decode the encrypted flag for ticket blob data.
		tReader.Reset(tBytes)
		if err := binary.Read(tReader, binary.LittleEndian, &tickets[i].Encrypted); err != nil {
			return nil, err
		}
		tBytes = tBytes[1:]

		// Parse the ticket blob data: [length]4 + [value]. Value should decrypt if encrypted.
		blobSize, blob, err := decodeSizeValue(tBytes, 1)
		if err != nil {
			return nil, err
		}
		tBytes = tBytes[SIZE_BYTES+blobSize*1:]

		// Decrypt and parse the blob data.
		tReader.Reset(blob)
		if tickets[i].Encrypted {
			if blob, err = key.Decrypt(blob); err != nil {
				return nil, err
			}
			tReader.Reset(blob)
			if !checkEncodingTag(tReader) {
				return nil, tagErr
			}
			if !checkAuthMagic(tReader) {
				return nil, magicErr
			}
			blob = blob[len(blob)-tReader.Len():]
		}
		if !checkEncodingTag(tReader) {
			return nil, tagErr
		}
		if err := binary.Read(tReader, binary.LittleEndian, &tickets[i].SecretId); err != nil {
			return nil, err
		}
		blob = blob[len(blob)-tReader.Len():]
		blobValueSize, blobValue, err := decodeSizeValue(blob, 1)
		if err != nil {
			return nil, err
		}
		if blobValueSize+SIZE_BYTES != len(blob) {
			return nil, fmt.Errorf("blob data is broken")
		}
		tickets[i].Blob = blobValue
	}
	return tickets, nil
}
