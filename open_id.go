package azuread

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

// OpenIDConfiguration from the discovery endpoint
type OpenIDConfiguration struct {
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	HTTPLogoutSupported               bool     `json:"http_logout_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	Issuer                            string   `json:"issuer"`
	ClaimsSupported                   []string `json:"claims_supported"`
	MicrosoftMultiRefreshToken        bool     `json:"microsoft_multi_refresh_token"`
	CheckSessionIframe                string   `json:"check_session_iframe"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
}

type openID struct {
	config    *OpenIDConfiguration
	keys      JWKKeys
	validator *JWTValidator
	tenantID  string
	clientID  string
}

// ValidToken is a validated token property
type ValidToken struct {
	Name       string
	GivenName  string
	FamilyName string
	Email      string
	Groups     []string
	Token      *JWTToken
}

// OpenID validates bearer tokens
type OpenID interface {
	Validate(string) (*ValidToken, error)
}

func (t *openID) Validate(bearerToken string) (*ValidToken, error) {
	token, err := t.validator.ParseAndValidate(bearerToken)
	if err != nil {
		return nil, err
	}
	log.Debugf("Validate(%#v)", token)
	iss := token.GetClaimString("iss")
	if iss != t.config.Issuer {
		return nil, fmt.Errorf("Issuer does not match")
	}
	tid := token.GetClaimString("tid")
	appid := token.GetClaimString("aud")
	if appid != t.clientID {
		return nil, fmt.Errorf("ClientID does not match")
	}
	if tid != t.tenantID {
		return nil, fmt.Errorf("TenantID does not match")
	}
	name := token.GetClaimString("name")

	givenName := token.GetClaimString("given_name")
	familyName := token.GetClaimString("family_name")
	groups := token.GetClaimStringArray("groups")
	uniqueName := token.GetClaimString("unique_name")
	return &ValidToken{
		Name:       name,
		GivenName:  givenName,
		FamilyName: familyName,
		Groups:     groups,
		Email:      uniqueName,
		Token:      token,
	}, nil
}

// NewOpenID creates a new open ID validator for the given client/tenantID
func NewOpenID(clientID, tenantID string) (OpenID, error) {
	cfg, err := GetConfiguration(tenantID)
	if err != nil {
		return nil, err
	}
	keys, err := GetSigningKeys(cfg.JwksURI)
	if err != nil {
		return nil, err
	}
	validator := NewJWTValidator(keys)
	return &openID{
		validator: validator,
		keys:      keys,
		config:    cfg,
		clientID:  clientID,
		tenantID:  tenantID,
	}, nil
}

// GetConfiguration gets the well-known OpenID Configuration for the tenantID given
func GetConfiguration(tenantID string) (*OpenIDConfiguration, error) {
	url := fmt.Sprintf("https://login.windows.net/%s/.well-known/openid-configuration", tenantID)
	log.Debugf("GetConfiguration: GET %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	openIDConfiguration := &OpenIDConfiguration{}
	if err := decoder.Decode(openIDConfiguration); err != nil {
		return nil, err
	}
	return openIDConfiguration, nil
}
