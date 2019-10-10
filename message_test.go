package gorados

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestMessageAuth(t *testing.T) {
	client := EntityName{ENTITY_CLIENT, -1}
	auth, err := NewMessageAuth(AUTH_USER)
	if err != nil {
		t.Fatal(err)
	}
	authData := []byte{
		0x1e, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 0, 0, 8, 0, 0, 0, 5, 0,
		0, 0, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if !bytes.Equal(auth.AuthData, authData) {
		t.Fatalf("wrong auth data: %+v", auth.AuthData)
	}
	t.Logf("%+v", auth)
	t.Logf("header size: %d", auth.HeaderSize())
	t.Logf("footer size: %d", auth.FooterSize())

	// Create message payload and header and footer.
	if err := auth.Encode(); err != nil {
		t.Fatal(err)
	}
	t.Logf("payload: %+v", auth.Payload)
	auth.CreateHeader(client, 1, 0, MSG_PRIO_DEFAULT, 1, 0)
	auth.CreateFooter(MSG_FOOTER_FLAG_LOSSY, 0)

	// Create message and marshal to binary bytes.
	data, err := auth.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("auth message: %+v, %d", data, len(data))
	var crc uint32
	binary.Read(bytes.NewBuffer(data[49:53]), binary.LittleEndian, &crc)
	t.Logf("0x%x", crc)
}

func TestMessageAuthReply(t *testing.T) {
	msg := &MessageAuthReply{
		Result: []byte{
			0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 32, 0, 0, 0, 1, 48, 0, 0, 0, 172, 83, 18,
			157, 226, 173, 162, 69, 244, 6, 98, 166, 71, 106, 202, 30, 127, 119, 217,
			85, 164, 110, 145, 225, 252, 96, 140, 243, 107, 104, 220, 61, 203, 133, 37,
			0, 87, 150, 49, 89, 85, 57, 109, 73, 143, 183, 100, 238, 0, 109, 0, 0, 0, 1,
			43, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 212, 209, 156, 226, 16, 94, 224, 45,
			75, 69, 3, 232, 113, 14, 133, 92, 40, 10, 213, 5, 61, 203, 113, 159, 201,
			192, 192, 163, 41, 228, 189, 65, 60, 145, 31, 126, 85, 68, 137, 238, 144,
			95, 12, 150, 66, 62, 12, 67, 245, 42, 230, 5, 88, 134, 44, 35, 174, 0, 6,
			58, 196, 159, 67, 149, 58, 159, 118, 79, 19, 197, 87, 53, 105, 128, 149,
			157, 7, 180, 176, 25, 137, 183, 78, 71, 168, 19, 209, 253, 50, 214, 87, 11,
			91, 42, 96, 21},
	}
	key := &CryptoKey{}
	rawKey := "AQAXzGxdPT7BIBAAVz8zMAw+70YdylosZcijng=="
	keyBytes, _ := base64.StdEncoding.DecodeString(rawKey)
	key.UnmarshalBinary(keyBytes)

	tickets, err := msg.GetSessionTickets(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", tickets)
}

func TestMessageMonSubscribe(t *testing.T) {
	msgSub := NewMessageMonSubscribe(shortHostname())
	msgSub.Add("config", &subscribeItem{})
	msgSub.Add("monmap", &subscribeItem{})
	msgSub.Encode()
	msgSub.CreateHeader(EntityName{ENTITY_CLIENT, -1}, 3, 0, MSG_PRIO_DEFAULT, 3, 0)
	msgSub.CreateFooter(MSG_FOOTER_FLAG_LOSSY, 0)
	b, _ := msgSub.MarshalBinary()
	hexdump(OUT, b)
	t.Logf("%+v", msgSub.Payload)
}
