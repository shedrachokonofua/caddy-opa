package opa_policy

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileOPA(t *testing.T) {
	adminPort := 29999
	// Basic OPA policy that allows GET requests and denies others
	policy := `
		package caddy.authz

		default allow = false

		allow {
			input.method == "GET"
		}
	`

	// Create Caddy configuration
	config := fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:%d
		http_port 44444
	}

	localhost:44444 {
		route / {
			opa_policy `+"`%s`"+`
			respond "hello"
		}
	}
	`, adminPort, policy)

	// Initialize tester
	tester := caddytest.NewTester(t)
	caddytest.Default.AdminPort = adminPort
	tester.InitServer(config, "caddyfile")

	// Test allowed GET request
	tester.AssertGetResponse("http://localhost:44444", 200, "hello")

	// Test denied POST request
	bodyContent := bytes.NewBufferString(`{"test": "data"}`)
	requestHeaders := []string{"Content-Type: application/json"}
	tester.AssertPostResponseBody("http://localhost:44444", requestHeaders, bodyContent, 403, "{\"message\":\"Forbidden\"}\n")

	// Test other HTTP methods
	tester.AssertPatchResponseBody("http://localhost:44444", requestHeaders, bodyContent, 403, "{\"message\":\"Forbidden\"}\n")
}
