package azure_activedirectory

import (
	"encoding/json"
	"net/http"
)

const DiscoveryKeysUrl = "/discovery/keys"

type KeysMetadata struct {
	Keys []KeyMetadata `json:keys`
}

type KeyMetadata struct {
	KeyType string `json:kty`
	Use string `json:use`
	KeyId string `json:kid`
	CertificateThumbprint string `json:x5t`
	CertificateChain []string `json:x5c`
	Modulus string `json:n`
	Exponent string `json:e`
}

type Key struct {
	KeyId     string
	Algorithm string
}

type KeyStore struct {
	Authority string
	Keys      map[string]*Key
}

func makeKeyStore(authority string) *KeyStore {
	store := new(KeyStore)
	store.Authority = authority
	store.Keys = getKeys(authority + DiscoveryKeysUrl)

	return store
}

func (ks KeyStore) getKey(kid string) *Key {
	return ks.Keys[kid]
}

func getKeys(store string) map[string]*Key {
	result, _ := http.DefaultClient.Get(store)

	data := json.NewDecoder(result.Body)

	return parseKeys(data)
}

func parseKeys(data *json.Decoder) map[string]*Key {
	var result KeysMetadata
	var keys = make(map[string]*Key)

	data.Decode(result)

	for _, key := range result.Keys {
		parsed_key := parseKey(key)

		keys[key.KeyId] = parsed_key
	}

	return keys
}

func parseKey(key KeyMetadata) *Key {
	result := new(Key)

	result.KeyId = key.KeyId
	result.Algorithm = key.KeyType

	return result
}