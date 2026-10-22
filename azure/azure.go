// Package azure implements the Azure AD / Microsoft Entra ID external provider driver.
//
// Import it for side effects to register the "azure" driver:
//
//	import _ "azugo.io/auth-provider/azure"
//
// The optional config option "tenant" pins the directory tenant (default "organizations"), and
// "tenants" (comma-separated directory IDs, or "*" for any) lists the directories that may sign
// in through the multi-tenant pseudo-tenants, which require it.
//
// Entra ID does not verify the email claim, so the default mapping marks it verified only when
// the optional xms_edov claim (email domain owner verified) is true; add xms_edov as an optional
// ID token claim in the app registration.
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
	anyTenant := slices.Contains(tenants, "*")
	multiTenant := tenant == "common" || tenant == "organizations"

	if multiTenant && len(tenants) == 0 {
		return nil, fmt.Errorf("azure: tenant %q admits every directory; list the allowed ones in tenants, or \"*\" for any", tenant)
	}

	c := oidc.Config{
		Issuer:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		ClockSkew:    cfg.EffectiveClockSkew(),
	}

	// The multi-tenant pseudo-tenants publish a "{tenantid}" issuer while tokens has directory ID
	if len(tenants) > 0 || multiTenant {
		c.IssuerCheck = func(iss string) error {
			tid, ok := strings.CutPrefix(iss, "https://login.microsoftonline.com/")
			if ok {
				tid, ok = strings.CutSuffix(tid, "/v2.0")
			}

			if !ok || tid == "" || strings.Contains(tid, "/") {
				return fmt.Errorf("unexpected issuer %q", iss)
			}

			if !anyTenant && !slices.ContainsFunc(tenants,
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

// DefaultClaimMapper for the standard mapping with the email verified only by xms_edov and the
// Entra ID preferred_username fallback for a missing email claim.
func (driver) DefaultClaimMapper() provider.ClaimMapper {
	return provider.ClaimMapperFunc(func(ctx context.Context, name string, raw map[string]any) (provider.UserInfo, error) {
		info, err := provider.MapStandardClaims(ctx, name, raw)
		if err != nil {
			return info, err
		}

		var verified bool

		switch v := raw["xms_edov"].(type) {
		case bool:
			verified = v
		case string:
			verified = strings.EqualFold(v, "true") || v == "1"
		case float64:
			verified = v == 1
		}

		if emails := info.Contacts[contract.ChannelEmail]; len(emails) > 0 {
			emails[0].Verified = verified
			info.Claims["email_verified"] = verified

			return info, nil
		}

		// A UPN is no proof of a mailbox, so it is never verified.
		if v, ok := raw["preferred_username"].(string); ok && strings.Contains(v, "@") {
			if info.Contacts == nil {
				info.Contacts = make(map[string][]contract.Contact, 1)
			}

			info.Contacts[contract.ChannelEmail] = []contract.Contact{
				{Address: v, Primary: true},
			}
			info.Claims["email_verified"] = false
		}

		return info, nil
	})
}
