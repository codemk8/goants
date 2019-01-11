package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	jose "gopkg.in/square/go-jose.v2"
)

type ecdsaSigner struct {
	ecdsaVerifier
	signer jose.Signer
}

// NewJSigner is, for the moment, a thin wrapper around Square's
// go-jose library to issue ECDSA-P256 JWS tokens.
func NewJSigner(filename string) (jose.Signer, error) {
	// Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}
	return signer, err
}

// Sign an authentcation token and return the serialized JWS
func (es *ecdsaSigner) Sign(token *AuthToken) (string, error) {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		// panic? what are the conditions under which this can fail?
		return "", err
	}
	jws, err := es.signer.Sign(tokenBytes)
	if err != nil {
		return "", err
	}
	signed, err := jws.CompactSerialize()
	if err != nil {
		return "", err
	}
	return signed, nil
}
