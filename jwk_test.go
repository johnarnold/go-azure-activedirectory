package azuread

import "testing"

func TestGetKeys(t *testing.T) {
	keys, err := GetSigningKeys("https://login.windows.net/common/discovery/keys")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	t.Logf("%#v", keys)
}
