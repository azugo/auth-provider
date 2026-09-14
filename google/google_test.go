package google

import (
	"context"
	"testing"

	"azugo.io/auth/contract"
	"azugo.io/auth/provider"

	"github.com/go-quicktest/qt"
)

func TestOpenDoesNotSupportRPInitiatedLogout(t *testing.T) {
	p, err := driver{}.Open(&contract.ExternalProviderConfig{
		Name: "gmail", Driver: "google", ClientID: "cid",
		RedirectURL: "https://app.example/auth/external/gmail/callback",
		Config:      map[string]string{"hd": "mycorp.com"},
	})
	qt.Assert(t, qt.IsNil(err))

	_, ok := p.(provider.Logouter)
	qt.Check(t, qt.IsFalse(ok))
}

func TestDefaultClaimMapperIsStandard(t *testing.T) {
	m := driver{}.DefaultClaimMapper()

	info, err := m.MapClaims(context.Background(), "gmail", map[string]any{
		"sub": "s1", "name": "Alice", "email": "alice@mycorp.com", "hd": "mycorp.com",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "s1"))
	qt.Check(t, qt.Equals(info.Email, "alice@mycorp.com"))
	qt.Check(t, qt.Equals(info.Claims["hd"], "mycorp.com"))
}

func TestDriverRegistered(t *testing.T) {
	m, err := provider.DefaultClaimMapper("google")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(m))
}
