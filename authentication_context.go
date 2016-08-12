package azure_activedirectory

import (
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/clientcredentials"
)

const OpenIdConfigurationUrl = "/.well-known/openid-configuration"

type AuthenticationContext struct {
	Authority string
}

func (ac AuthenticationContext) GetAuthority() string {
	return ac.Authority
}

func (ac AuthenticationContext) SetAuthority(authority string) {
	ac.Authority = authority
}

func (ac AuthenticationContext) AcquireToken(resource string, credential ClientCredential) AuthenticationResult {
	config := clientcredentials.Config{
		ClientID:     credential.ClientId,
		ClientSecret: credential.ClientSecret,
		TokenURL:     fmt.Sprintf("%s/oauth2/token"),
		Scopes:       []string{},
	}

	context := context.Background()

	result, err := config.Token(context)

	return authenticationResult(ac, result, err)
}
