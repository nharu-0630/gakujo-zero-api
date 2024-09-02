package tools

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"time"
)

func truncate(hs []byte) int {
	offset := int(hs[len(hs)-1] & 0x0F)
	p := hs[offset : offset+4]
	return (int(binary.BigEndian.Uint32(p)) & 0x7FFFFFFF) % 1000000
}

func hmacSHA1(key []byte, timestamp uint64) []byte {
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, timestamp)
	mac := hmac.New(sha1.New, key)
	mac.Write(cb)
	return mac.Sum(nil)
}

func TOTP(secret string, interval uint64) int {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return 0
	}
	return truncate(hmacSHA1(key, (uint64(time.Now().Unix()))/interval))
}
