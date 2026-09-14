// Package google implements the Google Workspace external provider driver.
//
// Import it for side effects to register the "google" driver:
//
//	import _ "azugo.io/auth-provider/google"
//
// The optional config option "hd" restricts sign-in to one Workspace domain (sent as the hd
// authorization parameter; verify the hd claim in a claim mapper for a hard guarantee).
package google

import (
	"fmt"
	"net/url"

	"azugo.io/auth/contract"
	"azugo.io/auth/provider"
	"azugo.io/auth/provider/oidc"
)

func init() {
	provider.Register("google", driver{})
}

type driver struct{}

// Open Google IdP provider driver that has no end_session_endpoint, so the provider does
// not support RP-initiated logout.
func (driver) Open(cfg *contract.ExternalProviderConfig) (provider.Provider, error) {
	c := oidc.Config{
		Issuer:       "https://accounts.google.com",
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		ClockSkew:    cfg.EffectiveClockSkew(),
		// Google historically issues both iss forms.
		IssuerCheck: func(iss string) error {
			if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
				return fmt.Errorf("unexpected issuer %q", iss)
			}

			return nil
		},
	}

	if hd := cfg.Config["hd"]; hd != "" {
		c.AuthParams = url.Values{"hd": {hd}}
	}

	return oidc.New(c), nil
}

// DefaultClaimMapper for Google driver.
func (driver) DefaultClaimMapper() provider.ClaimMapper {
	return provider.ClaimMapperFunc(provider.MapStandardClaims)
}
