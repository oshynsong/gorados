package gorados

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestNewSockAddr(t *testing.T) {
	for _, item := range []struct {
		input  *SockAddr
		actual *SockAddr
	}{
		{
			input:  NewSockAddr(nil, 0),
			actual: nil,
		},
		{
			input:  NewSockAddr(net.ParseIP("xxx"), 0),
			actual: nil,
		},
		{
			input:  NewSockAddr(net.ParseIP("10.190.75.13"), 6789),
			actual: &SockAddr{AF_INET, 6789, [4]byte{10, 190, 75, 13}},
		},
	} {
		if item.actual == nil && item.actual != item.input {
			t.Logf("result=%s actual=%s", item.input, item.actual)
			t.Fatal("NewSockAddr6() result not match")
		}
		str1, str2 := fmt.Sprintf("%s", item.input), fmt.Sprintf("%s", item.actual)
		if str1 != str2 {
			t.Logf("result=%s actual=%s", str1, str2)
			t.Fatal("NewSockAddr6 result not match")
		}
	}
}

func TestSockAddr(t *testing.T) {
	for _, item := range []struct {
		input        *SockAddr
		actual       [128]byte
		stringResult string
		toIPResult   net.IP
	}{
		{
			input:        &SockAddr{},
			actual:       [128]byte{},
			stringResult: "family=0,port=0,addr=0.0.0.0",
			toIPResult:   net.IPv4(0, 0, 0, 0),
		},
		{
			input:        &SockAddr{0x02, 6789, [4]byte{10, 190, 75, 13}},
			actual:       [128]byte{0x00, 0x02, 0x1a, 0x85, 0x0a, 0xbe, 0x4b, 0x0d},
			stringResult: "family=2,port=6789,addr=10.190.75.13",
			toIPResult:   net.IPv4(10, 190, 75, 13),
		},
	} {
		result, err := item.input.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("MarshalBinary result: %x", result)
		if !bytes.Equal(result, item.actual[:]) {
			t.Logf("result=%x actual=%x", result, item.actual[:])
			t.Fatal("MarshalBinary result not match")
		}

		if item.input.String() != item.stringResult {
			t.Logf("result=%s actual=%s", item.input, item.stringResult)
			t.Fatal("String() result not match")
		}

		if item.input.Size() != 128 {
			t.Fatal("Size() result not match")
		}

		if !item.input.AddrIP().Equal(item.toIPResult) {
			t.Logf("result=%s actual=%s", item.input.AddrIP(), item.toIPResult)
			t.Fatal("AddrIP() result not match")
		}
	}
}

func TestSockAddrUnmarshalBinary(t *testing.T) {
	for _, item := range []struct {
		input  [128]byte
		actual *SockAddr
	}{
		{
			input:  [128]byte{},
			actual: &SockAddr{},
		},
		{
			input:  [128]byte{0x02, 0x00, 0x1a, 0x85, 0x0a, 0xbe, 0x4b, 0x0d},
			actual: &SockAddr{0x02, 6789, [4]byte{10, 190, 75, 13}},
		},
	} {
		result := &SockAddr{}
		err := result.UnmarshalBinary(item.input[:])
		if err != nil {
			t.Fatal(err)
		}
		if result.Family != item.actual.Family {
			t.Logf("result=%x actual=%x", result.Family, item.actual.Family)
			t.Fatal("UnmarshalBinary result not match")
		}
		if result.Port != item.actual.Port {
			t.Logf("result=%x actual=%x", result.Port, item.actual.Port)
			t.Fatal("UnmarshalBinary result not match")
		}
		if !bytes.Equal(result.Addr[:], item.actual.Addr[:]) {
			t.Logf("result=%x actual=%x", result.Addr, item.actual.Addr)
			t.Fatal("UnmarshalBinary result not match")
		}
	}
}

func TestNewSockAddr6(t *testing.T) {
	for _, item := range []struct {
		input  *SockAddr6
		actual *SockAddr6
	}{
		{
			input:  NewSockAddr6(nil, 0),
			actual: nil,
		},
		{
			input:  NewSockAddr6(net.ParseIP("xxx"), 0),
			actual: nil,
		},
		{
			input:  NewSockAddr6(net.ParseIP("102:304::"), 6789),
			actual: &SockAddr6{AF_INET6, 6789, 0, [16]byte{0x01, 0x2, 0x3, 0x4}, 0},
		},
		{
			input:  NewSockAddr6(net.ParseIP("102:304::"), 6789, 1),
			actual: &SockAddr6{AF_INET6, 6789, 1, [16]byte{0x01, 0x2, 0x3, 0x4}, 0},
		},
		{
			input:  NewSockAddr6(net.ParseIP("ff02:304::"), 6789, 1),
			actual: &SockAddr6{AF_INET6, 6789, 1, [16]byte{0xff, 0x2, 0x3, 0x4}, 2},
		},
	} {
		if item.actual == nil && item.actual != item.input {
			t.Logf("result=%s actual=%s", item.input, item.actual)
			t.Fatal("NewSockAddr6() result not match")
		}
		if item.input != nil && item.input.Size() != 128 {
			t.Fatal("Size() result not match")
		}
		str1, str2 := fmt.Sprintf("%s", item.input), fmt.Sprintf("%s", item.actual)
		if str1 != str2 {
			t.Logf("result=%s actual=%s", str1, str2)
			t.Fatal("NewSockAddr6 result not match")
		}
	}
}

func TestSockAddr6(t *testing.T) {
	for _, item := range []struct {
		obj *SockAddr6
		raw [128]byte
	}{
		{
			obj: &SockAddr6{AF_INET6, 6789, 0, [16]byte{1, 2, 3, 4}, 0},
			raw: [128]byte{
				0x00, 0x0a, 0x1a, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2, 0x3, 0x4},
		},
	} {
		result, err := item.obj.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("MarshalBinary result: %x", result)
		if !bytes.Equal(result, item.raw[:]) {
			t.Logf("result=%x actual=%x", result, item.raw[:])
			t.Fatal("MarshalBinary result not match")
		}

		result2 := &SockAddr6{}
		if err = result2.UnmarshalBinary(item.raw[:]); err != nil {
			t.Fatal(err)
		}
		str1 := fmt.Sprintf("%s", result2)
		str2 := fmt.Sprintf("%s", item.obj)
		if str1 != str2 {
			t.Logf("result=%s actual=%s", str1, str2)
			t.Fatal("UnmarshalBinary result not match")
		}
	}
}

func TestEntityMarshalBinary(t *testing.T) {
	for _, item := range []struct {
		obj *EntityAddr
		raw [136]byte
	}{
		{
			obj: &EntityAddr{0, 0, NewSockAddr(net.IPv4(10, 190, 75, 13), 6789)},
			raw: [136]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x02, 0x1a, 0x85, 0x0a, 0xbe, 0x4b, 0x0d},
		},
		{
			obj: &EntityAddr{0, 0, NewSockAddr6(net.ParseIP("102:304::"), 6789)},
			raw: [136]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x1a, 0x85,
				0x00, 0x00, 0x00, 0x00, 0x01, 0x2, 0x3, 0x4},
		},
	} {
		result, err := item.obj.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("MarshalBinary result: %x", result)
		if !bytes.Equal(result, item.raw[:]) {
			t.Logf("result=%x actual=%x", result, item.raw[:])
			t.Fatal("MarshalBinary result not match")
		}

		result2 := &EntityAddr{}
		if err = result2.UnmarshalBinary(item.raw[:]); err != nil {
			t.Fatal(err)
		}
		t.Logf("UnmarshalBinary result: %v", result2)
		if result2.Type != item.obj.Type {
			t.Logf("result=%x actual=%x", result2.Type, item.obj.Type)
			t.Fatal("UnmarshalBinary result not match")
		}
		if result2.Nonce != item.obj.Nonce {
			t.Logf("result=%x actual=%x", result2.Nonce, item.obj.Nonce)
			t.Fatal("UnmarshalBinary result not match")
		}
		str1 := fmt.Sprintf("%s", result2.Address)
		str2 := fmt.Sprintf("%s", item.obj.Address)
		if str1 != str2 {
			t.Logf("result=%s actual=%s", str1, str2)
			t.Fatal("UnmarshalBinary result not match")
		}
	}
}

func TestCryptoKey(t *testing.T) {
	obj := &CryptoKey{
		Type:   1,
		Random: []byte{87, 63, 51, 48, 12, 62, 239, 70, 29, 202, 90, 44, 101, 200, 163, 158},
	}
	obj.Created.Second = 1567411223
	obj.Created.Nano = 549535293

	raw := []byte{
		0x01, 0x00, 0x17, 0xcc, 0x6c, 0x5d, 0x3d, 0x3e, 0xc1, 0x20,
		0x10, 0x00, 0x57, 0x3f, 0x33, 0x30, 0x0c, 0x3e, 0xef, 0x46,
		0x1d, 0xca, 0x5a, 0x2c, 0x65, 0xc8, 0xa3, 0x9e,
	}

	result, err := obj.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MarshalBinary result: %x", result)
	if !bytes.Equal(result, raw[:]) {
		t.Logf("result=%x actual=%x", result, raw[:])
		t.Fatal("MarshalBinary result not match")
	}

	result2 := &CryptoKey{}
	if err = result2.UnmarshalBinary(raw[:]); err != nil {
		t.Fatal(err)
	}
	t.Logf("UnmarshalBinary result: %v", result2)
	if result2.Type != obj.Type {
		t.Logf("result=%x actual=%x", result2.Type, obj.Type)
		t.Fatal("UnmarshalBinary result not match")
	}
	if result2.Created.Second != obj.Created.Second || result2.Created.Nano != obj.Created.Nano {
		t.Logf("result=%v actual=%v", result2.Created, obj.Created)
		t.Fatal("UnmarshalBinary result not match")
	}
	if !bytes.Equal(result2.Random, obj.Random) {
		t.Logf("result=%x actual=%x", result2.Random, obj.Random)
		t.Fatal("UnmarshalBinary result not match")
	}

	data := []byte{1}
	enc, err := obj.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := obj.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Logf("decrypt not match encrypt: %x, %x", dec, data)
		t.Fatal("decrypt encrypt result not match")
	}
}
