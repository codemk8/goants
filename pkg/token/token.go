package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	jose "github.com/square/go-jose"
)

const (
	curveName = "P-256"    // curveName is the name of the ECDSA curve
	curveJose = jose.ES256 // curveJose is the name of the JWS algorithm
)

var curveEll = elliptic.P256()

// AuthToken contains information about the authenticated user
type AuthToken struct {
	Username   string
	Isa        string // issued at
	Assertions map[string]string
}

// AuthTokenStatus defines the returned JSON to auth request from web
type AuthTokenStatus struct {
	Authenticated bool
	Username      string
	Isa           string
	Assertions    map[string]string
}

// GenerateKeypair generates a public and private ECDSA key, to be
// used for signing and verifying authentication tokens.
func GenerateKeypair(filename string) (err error) {
	priv, err := ecdsa.GenerateKey(curveEll, rand.Reader)
	if err != nil {
		return
	}
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename+".priv", keyPEM, os.FileMode(0600))
	if err != nil {
		return
	}
	pub := priv.Public()
	pubKeyPEM, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("Error marshalling public key: %v", err)
	}
	err = ioutil.WriteFile(filename+".pub", pubKeyPEM, os.FileMode(0644))
	return
}

// CheckKeyPair checks of key pairs exist
func CheckKeyPair(filename string) (err error) {
	privFilename := filename + ".priv"
	pubFilename := filename + ".pub"
	_, err = os.Stat(privFilename)
	if os.IsNotExist(err) {
		return
	}
	_, err = os.Stat(pubFilename)
	if os.IsNotExist(err) {
		return
	}
	return nil
}
