package azure

import (
	"context"
	"maps"
	"testing"

	"azugo.io/auth/contract"
	"azugo.io/auth/provider"

	"github.com/go-quicktest/qt"
)

func TestOpenSupportsRPInitiatedLogout(t *testing.T) {
	p, err := driver{}.Open(&contract.ExternalProviderConfig{
		Name: "corp", Driver: "azure", ClientID: "cid",
		RedirectURL: "https://app.example/auth/external/corp/callback",
		Config:      map[string]string{"tenants": "a"},
	})
	qt.Assert(t, qt.IsNil(err))

	_, ok := p.(provider.Logouter)
	qt.Check(t, qt.IsTrue(ok))
}

func TestDefaultClaimMapperPreferredUsernameFallback(t *testing.T) {
	m := driver{}.DefaultClaimMapper()

	info, err := m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "name": "Alice", "preferred_username": "alice@corp.example", "xms_edov": true,
	})
	qt.Assert(t, qt.IsNil(err))

	// A UPN is never verified, whatever xms_edov says.
	qt.Check(t, qt.DeepEquals(info.Contacts[contract.ChannelEmail], []contract.Contact{{Address: "alice@corp.example", Primary: true}}))
	qt.Check(t, qt.Equals(info.Claims["email_verified"], any(false)))

	// A non-email preferred_username is not used.
	info, err = m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "preferred_username": "alice",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(info.Contacts[contract.ChannelEmail], 0))

	// An explicit email claim wins.
	info, err = m.MapClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "email": "real@corp.example", "preferred_username": "alias@corp.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Contacts[contract.ChannelEmail][0].Address, "real@corp.example"))
}

func TestDefaultClaimMapperVerifiesEmailOnlyByDomainOwner(t *testing.T) {
	m := driver{}.DefaultClaimMapper()

	for _, tc := range []struct {
		claims   map[string]any
		verified bool
	}{
		{map[string]any{}, false},
		{map[string]any{"email_verified": true}, false},
		{map[string]any{"xms_edov": false}, false},
		{map[string]any{"xms_edov": true}, true},
		{map[string]any{"xms_edov": "1"}, true},
		{map[string]any{"xms_edov": float64(1)}, true},
	} {
		raw := map[string]any{"sub": "s1", "email": "alice@corp.example"}
		maps.Copy(raw, tc.claims)

		info, err := m.MapClaims(context.Background(), "corp", raw)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(info.Contacts[contract.ChannelEmail][0].Verified, tc.verified), qt.Commentf("%v", tc.claims))
		qt.Check(t, qt.Equals(info.Claims["email_verified"], any(tc.verified)), qt.Commentf("%v", tc.claims))
	}
}

func TestOpenRequiresTenantsForMultiTenant(t *testing.T) {
	open := func(config map[string]string) error {
		_, err := driver{}.Open(&contract.ExternalProviderConfig{
			Name: "corp", Driver: "azure", ClientID: "cid",
			RedirectURL: "https://app.example/auth/external/corp/callback",
			Config:      config,
		})

		return err
	}

	// Every directory is admitted only when asked for.
	qt.Check(t, qt.ErrorMatches(open(nil), `azure: tenant "organizations" admits every directory.*`))
	qt.Check(t, qt.ErrorMatches(open(map[string]string{"tenant": "common"}), `azure: tenant "common" admits every directory.*`))
	qt.Check(t, qt.IsNil(open(map[string]string{"tenants": "*"})))
	qt.Check(t, qt.IsNil(open(map[string]string{"tenant": "common", "tenants": "a, b"})))

	// A single directory needs no list.
	qt.Check(t, qt.IsNil(open(map[string]string{"tenant": "11111111-2222-3333-4444-555555555555"})))
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
