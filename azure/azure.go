// Package azure implements the Azure AD / Microsoft Entra ID external provider driver.
//
// Import it for side effects to register the "azure" driver:
//
//	import _ "azugo.io/auth-provider/azure"
//
// The optional config option "tenant" pins the directory tenant (default "organizations"), and
// "tenants" (comma-separated directory IDs) restricts which directories may sign in through the
// multi-tenant pseudo-tenants.
package azure

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"azugo.io/auth/contract"
	"azugo.io/auth/provider"
	"azugo.io/auth/provider/oidc"
)

func init() {
	provider.Register("azure", driver{})
}

type driver struct{}

// Open Azure IdP provider driver.
func (driver) Open(cfg *contract.ExternalProviderConfig) (provider.Provider, error) {
	tenant := cfg.Config["tenant"]
	if tenant == "" {
		tenant = "organizations"
	}

	tenants := strings.FieldsFunc(cfg.Config["tenants"], func(r rune) bool { return r == ',' || unicode.IsSpace(r) })

	c := oidc.Config{
		Issuer:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		ClockSkew:    cfg.EffectiveClockSkew(),
	}

	// The multi-tenant pseudo-tenants publish a "{tenantid}" issuer while tokens has directory ID
	if len(tenants) > 0 || tenant == "common" || tenant == "organizations" {
		c.IssuerCheck = func(iss string) error {
			tid, ok := strings.CutPrefix(iss, "https://login.microsoftonline.com/")
			if ok {
				tid, ok = strings.CutSuffix(tid, "/v2.0")
			}

			if !ok || tid == "" || strings.Contains(tid, "/") {
				return fmt.Errorf("unexpected issuer %q", iss)
			}

			if len(tenants) > 0 && !slices.ContainsFunc(tenants,
				func(t string) bool {
					return strings.EqualFold(t, tid)
				},
			) {
				return fmt.Errorf("issuer tenant %q is not allowed", tid)
			}

			return nil
		}
	}

	return &oidc.LogoutProvider{Provider: oidc.New(c)}, nil
}

// DefaultClaimMapper for the standard mapping with the Entra ID preferred_username fallback
// for a missing email claim.
func (driver) DefaultClaimMapper() provider.ClaimMapper {
	return provider.ClaimMapperFunc(func(ctx context.Context, name string, raw map[string]any) (provider.UserInfo, error) {
		info, err := provider.MapStandardClaims(ctx, name, raw)
		if err != nil {
			return info, err
		}

		if info.Email == "" {
			if v, ok := raw["preferred_username"].(string); ok && strings.Contains(v, "@") {
				info.Email = v
			}
		}

		return info, nil
	})
}
