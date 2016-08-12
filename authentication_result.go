package azure_activedirectory

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"time"
)

const Oauth2AuthorizationHeader = "Bearer "

var keyStore map[string]*KeyStore = make(map[string]*KeyStore)

type AuthenticationResult struct {
	TokenType    string
	AccessToken  string
	Error        string
	RefreshToken string
	ExpiresOn    time.Time
	TenantId     string
}

func azureKeyFunc(ac AuthenticationContext) func(token *jwt.Token) (interface{}, error) {
	if keyStore[ac.Authority] == nil {
		keyStore[ac.Authority] = makeKeyStore(ac.Authority)
	}

	return func(token *jwt.Token) (interface{}, error) {
		key_id := token.Header["kid"].(string)
		key := keyStore[ac.Authority].getKey(key_id)

		if key != nil {
			return key, nil
		}

		return nil, errors.New("Key not found")
	}
}

func authenticationResult(ctx AuthenticationContext, token *oauth2.Token, err error) AuthenticationResult {
	result := AuthenticationResult{}
	claims := jwt.MapClaims{}

	if err != nil {
		result.Error = err.Error()
		return result
	}

	jwt_token, jwt_err := jwt.ParseWithClaims(token.AccessToken, claims, azureKeyFunc(ctx))

	if jwt_token.Valid == false {
		result.Error = "JWT token is not valid"
		return result
	}

	if jwt_err != nil {
		result.Error = jwt_err.Error()
		return result
	}

	result.Error = ""
	result.TenantId = claims["tid"].(string)
	result.AccessToken = token.AccessToken
	result.TokenType = token.TokenType
	result.ExpiresOn = token.Expiry

	return result
}

func (ar AuthenticationResult) createAuthorizationHeader() string {
	return Oauth2AuthorizationHeader + ar.AccessToken
}
