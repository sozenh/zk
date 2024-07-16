package zk

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Handle the SASL authentification.
const (
	zkSaslMd5Uri      = "zookeeper/zk-sasl-md5"
	zkSaslAuthQop     = "auth"
	zkSaslAuthIntQop  = "auth-int"
	zkSaslAuthConfQop = "auth-conf"
)

func getHexMd5(s string) string {
	bs := []byte(s)
	hash := ""
	sum := md5.Sum(bs)
	for _, b := range sum {
		hash += fmt.Sprintf("%02x", b)
	}
	return hash
}

func getMd5(s string) string {
	bs := []byte(s)
	sum := md5.Sum(bs)
	return string(sum[:])
}

func doubleQuote(s string) string {
	return `"` + s + `"`
}

func rmDoubleQuote(s string) string {
	leng := len(s)
	return s[1 : leng-1]
}

func getUserPassword(auth []byte) (string, string) {
	userPassword := string(auth)

	split := strings.SplitN(userPassword, ":", 2)

	return split[0], split[1]
}

type SASL struct {
	Nc     int
	Qop    string
	Realm  string
	Nonce  string
	CNonce string

	User     string
	Password string
}

func (r SASL) genA1() string {
	hexStr := fmt.Sprintf("%s:%s:%s", r.User, r.Realm, r.Password)
	keyHash := fmt.Sprintf("%s:%s:%s", getMd5(hexStr), r.Nonce, r.CNonce)

	return getHexMd5(keyHash)
}

func (r SASL) genChallenge() string {
	a1 := r.genA1()
	a2 := getHexMd5(fmt.Sprintf("%s:%s", "AUTHENTICATE", zkSaslMd5Uri))

	rv := fmt.Sprintf("%s:%s:%08x:%s:%s:%s", a1, r.Nonce, r.Nc, r.CNonce, r.Qop, a2)

	return getHexMd5(rv)
}

// GenSaslChallenge refers to RFC2831 to generate a md5-digest challenge.
func (r SASL) GenSaslChallenge() (string, error) {
	if r.User == "" || r.Password == "" {
		return "", errors.New("found invalid user&password")
	}

	r.Nc = 1
	r.Qop = zkSaslAuthQop // Only "auth" qop supports so far.

	// for unittest.
	if r.CNonce == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(65535))
		if err != nil {
			return "", err
		}
		r.CNonce = fmt.Sprintf("%s", n)
	}

	fileds := map[string]string{
		"qop":        r.Qop,
		"response":   r.genChallenge(),
		"username":   doubleQuote(r.User),
		"realm":      doubleQuote(r.Realm),
		"nonce":      doubleQuote(r.Nonce),
		"cnonce":     doubleQuote(r.CNonce),
		"digest-uri": doubleQuote(zkSaslMd5Uri),
		"nc":         fmt.Sprintf("%08x", r.Nc),
	}

	items := make([]string, 0, len(fileds))

	for k, v := range fileds {
		items = append(items, fmt.Sprintf("%s=%s", k, v))
	}

	return strings.Join(items, ","), nil
}

// Decode decodes a md5-digest ZK SASL response.
func (r setSaslResponse) Decode(buf []byte) (int, error) {

	// Discard the first 4 bytes, they are not used here.
	// According to RFC, the payload is inform of k1=v,k2=v, some of the values maybe enclosure with double quote(").
	payload := string(buf[4:])

	fmt.Println(payload)
	fmt.Println(string(buf))
	splitPayload := strings.Split(payload, ",")

	if len(splitPayload) == 0 {
		return 0, errors.New("invalid sasl payload")
	}

	r.Nonce = ""
	r.Realm = ""
	r.RspAuth = ""

	for _, item := range splitPayload {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return 0, errors.New("invalid sasl payload format")
		}

		key := strings.ToLower(kv[0])
		if key == "nonce" {
			r.Nonce = rmDoubleQuote(kv[1])
		} else if key == "realm" {
			r.Realm = rmDoubleQuote(kv[1])
		} else if key == "rspauth" {
			r.RspAuth = kv[1]
		}
	}

	return len(buf), nil
}
