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
  route / {
    opa_policy `
      package caddy.authz

      default allow = false

      allow {
        input.method == "GET"
        input.path == "/public"
      }

      allow {
        input.method == "POST"
        input.path == "/private"
        input.user == "admin"
      }
    `

    reverse_proxy localhost:8080
  }
}
```
