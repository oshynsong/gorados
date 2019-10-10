package gorados

import (
	"bytes"
	"fmt"
	"testing"
)

func TestCalculateCrc32(t *testing.T) {
	for _, item := range []struct {
		input  []byte
		actual uint32
	}{
		{
			input:  []byte{},
			actual: 0,
		},
		{
			input:  []byte{1},
			actual: 0xf26b8303,
		},
		{
			input: []byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 127, 0, 1, 0, 60, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0,
			},
			actual: 0xe2ab4b69,
		},
		{
			input: []byte{
				0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x33, 0x00, 0xc4, 0x00, 0x01, 0x00, 0x45, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda, 0x1e,
				0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			},
			actual: 0xc1d60017,
		},
	} {
		crc := calculateCrc32(item.input)
		output := fmt.Sprintf("result: 0x%x, actual: 0x%x", crc, item.actual)
		if crc != item.actual {
			t.Fatal("FAIL: " + output)
		} else {
			t.Log("PASS: " + output)
		}
	}
}

func TestEncodeSizeValue(t *testing.T) {
	for _, item := range []struct {
		size   int
		value  int32
		actual []byte
	}{
		{
			size:   -1,
			actual: nil,
		},
		{
			size:   0,
			actual: []byte{0, 0, 0, 0},
		},
		{
			size:   1,
			value:  32,
			actual: []byte{1, 0, 0, 0, 32, 0, 0, 0},
		},
	} {
		result, err := encodeSizeValue(item.size, item.value)
		output := fmt.Sprintf("input: %d, %v; result: %v, actual: %v. err: %v",
			item.size, item.value, result, item.actual, err)
		if !bytes.Equal(result, item.actual) {
			t.Fatal("FAIL: " + output)
		} else {
			t.Log("PASS: " + output)
		}
	}
}

func TestDecodeSizeValue(t *testing.T) {
	for _, item := range []struct {
		input       []byte
		unit        int
		actualSize  int
		actualValue []byte
	}{
		{
			input: []byte{0xff, 0xff, 0xff, 0xff},
			unit:  1,
		},
		{
			input: []byte{0, 0, 0, 0},
			unit:  1,
		},
		{
			input:       []byte{1, 0, 0, 0, 1, 0, 0, 0},
			unit:        4,
			actualSize:  1,
			actualValue: []byte{1, 0, 0, 0},
		},
	} {
		size, data, err := decodeSizeValue(item.input, item.unit)
		output := fmt.Sprintf("input: %v, %d; result: %d, %v, actual: %d, %v. err: %v",
			item.input, item.unit, size, data, item.actualSize, item.actualValue, err)
		if size != item.actualSize || !bytes.Equal(data, item.actualValue) {
			t.Fatal("FAIL: " + output)
		} else {
			t.Log("PASS: " + output)
		}
	}
}

func TestAesCrypt(t *testing.T) {
	for _, item := range []struct {
		key   []byte
		input []byte
	}{
		{
			key: []byte{
				0x4c, 0x80, 0x38, 0x96, 0x5d, 0x57, 0xbd, 0x51,
				0xf2, 0xb7, 0x69, 0xaf, 0xb0, 0x0c, 0xda, 0x6d,
			},
			input: []byte{0xff, 0xff, 0xff, 0xff},
		},
	} {
		crypted, err := aesEncrypt(item.key, item.input, []byte(AUTH_AES_IV))
		output := fmt.Sprintf("input: %v; result: %d, err: %v", item.input, crypted, err)
		if err != nil {
			t.Fatal("FAIL: " + output)
		} else {
			t.Log("PASS: " + output)
		}

		decrypted, err := aesDecrypt(item.key, crypted, []byte(AUTH_AES_IV))
		output = fmt.Sprintf("input: %v; result: %d, err: %v", item.input, decrypted, err)
		if err != nil || !bytes.Equal(item.input, decrypted) {
			t.Fatal("FAIL: " + output)
		} else {
			t.Log("PASS: " + output)
		}
	}
}
