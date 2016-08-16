package azuread

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

import "encoding/base64"

// ParseRSAPublicKeyFromPEMBody returns an *rsa.PublicKey by parsing the given p
func ParseRSAPublicKeyFromPEMBody(body []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse the key
	var parsed interface{}
	if parsed, err = x509.ParsePKIXPublicKey(body); err != nil {
		if cert, err := x509.ParseCertificate(body); err == nil {
			parsed = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsed.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("Key not a RSA PublicKey: %T", parsed)
	}

	return pkey, nil
}

// JWKKeys is a map of 'kid' => RSA Public Key
type JWKKeys map[string]*rsa.PublicKey

// JWKeysResponse is a response from the key discovery endpoint
type JWKeysResponse struct {
	Keys []*JWK `json:"keys"`
}

// JWK is an instance of a key
type JWK struct {
	KeyType              string   `json:"kty"`
	PublicKeyUseage      string   `json:"use"`
	KeyID                string   `json:"kid"`
	X509SHA1Thumprint    string   `json:"x5t"`
	X509CertificateChain []string `json:"x5c"`
}

// GetSigningKeys gets the JWK Keys from the given URL
func GetSigningKeys(url string) (JWKKeys, error) {
	log.Debugf("GetSigningKeys: GET %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	jwkResponse := &JWKeysResponse{}
	if err := decoder.Decode(jwkResponse); err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwkResponse.Keys {
		if jwk.PublicKeyUseage != "sig" {
			log.Debugf("Skip key %s because usage %s != sig", jwk.KeyID, jwk.PublicKeyUseage)
			continue
		}
		if len(jwk.X509CertificateChain) == 0 {
			continue
		}
		pemBody, err := base64.StdEncoding.DecodeString(jwk.X509CertificateChain[0])
		if err != nil {
			return nil, err
		}
		cert, err := ParseRSAPublicKeyFromPEMBody(pemBody)
		if err != nil {
			return nil, err
		}
		log.Debugf("Parsed public key %s", jwk.KeyID)
		keys[jwk.KeyID] = cert
	}
	return keys, nil
}
