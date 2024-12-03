# caddy-opa

This is a simple Caddy plugin that allows you to use Open Policy Agent (OPA) to enforce access control policies on your caddy server routes.

## Installation

```shell
xcaddy build --with github.com/shedrachokonofua/caddy-opa
```

## Usage

```caddy
{
  http_port 8080
}

example.com {
  route /* {
    opa_policy `
      package caddy.authz

      default allow = false

      # Parse JWT from Authorization header
      token := io.jwt.decode(trim_prefix(input.headers.Authorization, "Bearer "))

      allow {
        # Role-based access
        token.payload.roles[_] == "admin"
        input.path.startswith("/admin/")
      }

      allow {
        # Tenant isolation
        token.payload.tenant_id == input.headers.X-Tenant-ID
        input.method == "GET"
      }

      allow {
        # Allow unauthenticated users to access public routes
        input.path.startswith("/public/")
        input.method == "GET"
      }
    `

    reverse_proxy localhost:8080
  }
}
```
