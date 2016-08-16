package azuread

import "github.com/dgrijalva/jwt-go"
import "fmt"
import "errors"

import log "github.com/Sirupsen/logrus"

// JWTValidator validates JWT tokenIDs
type JWTValidator struct {
	Keys JWKKeys
}

// JWTToken is a raw token and its serialized form
type JWTToken struct {
	Raw   string
	Token *jwt.Token
}

// GetClaimString retreives a claim as a string
func (t *JWTToken) GetClaimString(key string) string {
	value, ok := t.Token.Claims[key]
	if !ok {
		return ""
	}
	str, ok := value.(string)
	if !ok {
		return ""
	}
	return str
}

// GetClaimStringArray retreives a claim as a string slice
func (t *JWTToken) GetClaimStringArray(key string) []string {
	value, ok := t.Token.Claims[key]
	if !ok {
		return nil
	}
	switch t := value.(type) {
	case []string:
		return t
	case []interface{}:
		return toStringArray(t)
	}
	return nil
}

func toStringArray(in []interface{}) []string {
	var arr []string
	for _, e := range in {
		arr = append(arr, fmt.Sprintf("%v", e))
	}
	return arr
}

var (
	// ErrKeyNotFound is an error returned when the JWK 'kid' is not found
	ErrKeyNotFound = errors.New("JWK Key not found")
	// ErrTokenNotValid is an error returned when the JWT token is invalid
	ErrTokenNotValid = errors.New("JWT Token is not valid")
)

// NewJWTValidator creates a new JWTValidator which will validate against the given keys
func NewJWTValidator(keys JWKKeys) *JWTValidator {
	return &JWTValidator{
		Keys: keys,
	}
}

// ParseAndValidate parses and validates a JWT bearer token
func (v *JWTValidator) ParseAndValidate(tokenID string) (*JWTToken, error) {
	token, err := jwt.Parse(tokenID, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid := token.Header["kid"].(string)
		log.Debugf("Finding keyID: %s", kid)
		key := v.Keys[kid]
		if key == nil {
			return nil, ErrKeyNotFound
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, ErrTokenNotValid
	}
	return &JWTToken{Raw: tokenID, Token: token}, nil
}
