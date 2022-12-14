package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

func GenerateTotp(secret string, interval int64) string {
	t := time.Now().Unix() / interval

	return GenerateHotp(secret, t)
}

func GenerateHotp(secret string, event int64) string {
	key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(secret))

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(event))

	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	o := (h[19] & 15)

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	binary.Read(r, binary.BigEndian, &header)

	h12 := (int(header) & 0x7fffffff) % 1000000

	//Converts number as a string
	otp := strconv.Itoa(int(h12))

	return otp
}
