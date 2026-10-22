# Azugo auth external provider drivers

External identity provider drivers for [`azugo.io/auth`](https://github.com/azugo/auth).
Each driver package self-registers in `init()` - import it to register and reference it by
driver name in the auth configuration:

```go
import (
	_ "azugo.io/auth-provider/azure"
	_ "azugo.io/auth-provider/google"
)
```

```yaml
auth:
  providers:
    - name: corp
      driver: azure
      client_id: ...
      client_secret: ...
      redirect_url: https://app.example/auth/external/corp/callback
      config:
        tenant: organizations
        tenants: 11111111-2222-3333-4444-555555555555
    - name: gmail
      driver: google
      client_id: ...
      client_secret: ...
      redirect_url: https://app.example/auth/external/gmail/callback
      config:
        hd: mycorp.com
```

## Drivers

| Package | Driver name | Notes |
|---|---|---|
| `azure` | `azure` | Azure AD / Microsoft Entra ID. Optional `tenant` config option (default `organizations`); `tenants` (comma-separated directory IDs, or `*` for any) is required with `common`/`organizations`. The email counts as verified only when the `xms_edov` optional claim is true, so add `xms_edov` to the app registration's ID token claims. Supports RP-initiated (federated) logout. |
| `google` | `google` | Google Workspace. Optional `hd` config option to restrict sign-in to one Workspace domain; no RP-initiated logout (Google has no `end_session_endpoint`). |

Both drivers are thin wrappers over the generic OIDC authorization-code core in
`azugo.io/auth/provider/oidc` - use that package directly to integrate any other
standards-compliant OIDC identity provider.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
