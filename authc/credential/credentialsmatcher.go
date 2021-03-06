package credential

import (
	"github.com/jalkanen/kuro/authc"
	"hash"
	"crypto"
	"strings"
	"io"
	"bytes"
)

// CredentialsMatcher provides matching services during the actual authentication
// of the user.
type CredentialsMatcher interface {
	Match(authc.AuthenticationToken, authc.AuthenticationInfo) bool
}

// A CredentialsMatcher for plaintext passwords.
type PlainText struct {
}

// A CredentialsMatcher for hashed passwords.
type Hashed struct {
	hasher         hash.Hash
	hashAlgorithm  string
	hashIterations int32
}

// Return a new Hashed credentialsmatcher for the given algorithm and iterations.
// Salt is provided by the individual AuthenticationInfo if it implements SaltedAuthenticationInfo.
// Available algorithms are: sha1, sha256, sha384, sha512.
func NewHashed(algorithm string, iterations int32) *Hashed {
	m := new(Hashed)

	m.hashAlgorithm = algorithm
	m.hashIterations = max(iterations, 1)

	return m
}

func getHash(algo string) hash.Hash {
	switch strings.ToLower(algo) {
	case "sha1":
		return crypto.SHA1.New()
	case "sha256":
		return crypto.SHA256.New()
	case "sha384":
		return crypto.SHA384.New()
	case "sha512":
		return crypto.SHA512.New()
	}
	return nil
}

func (cm *Hashed) Match(token authc.AuthenticationToken, info authc.AuthenticationInfo) bool {
	hash := getHash(cm.hashAlgorithm)
	var creds []byte

	creds = token.Credentials().([]byte)

	if salt, ok := info.(authc.SaltedAuthenticationInfo); ok {
		hash.Write(salt.CredentialsSalt())
	}

	var i int32

	for i = 0; i < cm.hashIterations; i++ {
		io.Copy(hash, bytes.NewReader(creds) )
	}

	final := hash.Sum(nil)

	return bytes.Equal(final, info.Credentials().([]byte))
}

func max(x, y int32) int32 {
	if x > y {
		return x
	}
	return y
}

// Returns a plain text matcher.  Note that using this is inherently unsafe, as it means
// that your system has passwords stored in plaintext.
func NewPlain() *PlainText {
	return &PlainText{}
}

func (cm *PlainText) Match(token authc.AuthenticationToken, info authc.AuthenticationInfo) bool {
	var givenPwd []byte
	// FIXME: Don't ignore errors
	switch token.Credentials().(type) {
	case string:
		givenPwd = []byte(token.Credentials().(string))
	case []byte:
		givenPwd = token.Credentials().([]byte)
	}

	storedPwd, _ := info.Credentials().(string)

	return bytes.Equal( givenPwd, []byte(storedPwd) )
}
