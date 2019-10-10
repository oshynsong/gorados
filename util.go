// util.go - defines the utility functions for current package

package gorados

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	SIZE_BYTES = 4 // type of size is uint32 and need 4 bytes to store
)

var OUT, ERR = os.Stdout, os.Stderr

// encodeSizeValue encodes the object with its size(in bytes) prefixed. The format is
// as follows: binary.Size(v) + raw bytes v. Value must be fixed-size value, or slice
// of or pointer to such data.
func encodeSizeValue(size int, v interface{}) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("encoding value size %d should not be less than 0", size)
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint32(size)); err != nil {
		return nil, err
	}
	if size > 0 {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// decodeSizeValue decodes the prefixed size and obtain the data part from the next buffer.
func decodeSizeValue(input []byte, unit int) (size int, data []byte, err error) {
	if input == nil || len(input) == 0 {
		return
	}
	var s int32
	buf := bytes.NewBuffer(input)
	if err = binary.Read(buf, binary.LittleEndian, &s); err != nil {
		return
	}
	if s < 0 {
		return size, nil, fmt.Errorf("invalid encoding value size: %d", size)
	}
	size = int(s)

	prefixSize := binary.Size(s)
	dataSize := size * unit
	data = input[prefixSize : prefixSize+dataSize : prefixSize+dataSize]
	return
}

// aesEncrypt encrypt the origin data pad with PKCS#7 by the given key.
func aesEncrypt(key, origin, iv []byte) ([]byte, error) {
	keySize := len(key)
	if keySize != 16 && keySize != 24 && keySize != 32 { // refer to AES-128/AES-192/AES-256
		return nil, fmt.Errorf("invalid key size: %d", keySize)
	}
	if len(iv) != keySize {
		return nil, fmt.Errorf("size(%d) of iv is not equal to the key size(%d)", len(iv), keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	padSize := blockSize - len(origin)%blockSize
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	origin = append(origin, pad...)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origin))
	blockMode.CryptBlocks(crypted, origin)
	return crypted, nil
}

// aesDecrypt decrypt the origin data with key which may be padding with PKCS#7.
func aesDecrypt(key, origin, iv []byte) ([]byte, error) {
	keySize := len(key)
	if keySize != 16 && keySize != 24 && keySize != 32 { // refer to AES-128/AES-192/AES-256
		return nil, fmt.Errorf("invalid key size: %d", keySize)
	}
	if len(iv) != keySize {
		return nil, fmt.Errorf("size(%d) of iv is not equal to the key size(%d)", len(iv), keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	result := make([]byte, len(origin))
	blockMode.CryptBlocks(result, origin)
	size := len(result)
	return result[:(size - int(result[size-1]))], nil
}

func hexdump(w io.Writer, data []byte) {
	fmt.Fprintln(w, hex.Dump(data))
}

func checkEncodingTag(r io.Reader) bool {
	var tag uint8
	if err := binary.Read(r, binary.LittleEndian, &tag); err != nil {
		return false
	}
	if tag != ENCODING_TAG {
		return false
	}
	return true
}

func checkAuthMagic(r io.Reader) bool {
	var magic uint64
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return false
	}
	if magic != AUTH_ENC_MAGIC {
		return false
	}
	return true
}

func hostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

func shortHostname() string {
	h := hostname()
	pos := strings.Index(h, ".")
	if pos != -1 {
		return h[:pos]
	}
	return h
}
