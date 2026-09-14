package azure

import (
	"context"
	"testing"

	"azugo.io/auth/contract"
	"azugo.io/auth/provider"

	"github.com/go-quicktest/qt"
)

func TestOpenSupportsRPInitiatedLogout(t *testing.T) {
	p, err := driver{}.Open(&contract.ExternalProviderConfig{
		Name: "corp", Driver: "azure", ClientID: "cid",
		RedirectURL: "https://app.example/auth/external/corp/callback",
	})
	qt.Assert(t, qt.IsNil(err))

	_, ok := p.(provider.Logouter)
	qt.Check(t, qt.IsTrue(ok))
}

func TestDefaultClaimMapperPreferredUsernameFallback(t *testing.T) {
	m := driver{}.DefaultClaimMapper()

	info, err := m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "name": "Alice", "preferred_username": "alice@corp.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "alice@corp.example"))

	// A non-email preferred_username is not used.
	info, err = m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "preferred_username": "alice",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, ""))

	// An explicit email claim wins.
	info, err = m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "email": "real@corp.example", "preferred_username": "alias@corp.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "real@corp.example"))
}

func TestDriverRegistered(t *testing.T) {
	m, err := provider.DefaultClaimMapper("azure")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(m))
}

func TestOpenParsesTenants(t *testing.T) {
	p, err := driver{}.Open(&contract.ExternalProviderConfig{
		Name: "corp", Driver: "azure", ClientID: "cid",
		RedirectURL: "https://app.example/auth/external/corp/callback",
		Config:      map[string]string{"tenant": "consumers", "tenants": " a, b "},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(p))
}
