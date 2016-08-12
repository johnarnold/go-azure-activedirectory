package azure_activedirectory

type ClientCredential struct {
	ClientId     string
	ClientSecret string
}

func (cc ClientCredential) GetClientId() string {
	return cc.ClientId
}
