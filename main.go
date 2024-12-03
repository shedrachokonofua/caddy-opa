package opa_policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("opa_policy", parseCaddyfileHandler)
	caddy.RegisterModule(CaddyOpaMiddleware{})
}

type CaddyOpaMiddleware struct {
	Policy string
	logger *zap.Logger
}

func (CaddyOpaMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.opa_policy",
		New: func() caddy.Module { return new(CaddyOpaMiddleware) },
	}
}

func (m *CaddyOpaMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

type Input struct {
	Method   string                 `json:"method"`
	Path     string                 `json:"path"`
	Headers  map[string][]string    `json:"headers"`
	BodyJson map[string]interface{} `json:"body_json"`
}

type Output struct {
	Allow      bool
	StatusCode int
	Message    string
}

func NewInputFromRequest(r *http.Request) *Input {
	var bodyJson map[string]interface{}

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	json.Unmarshal(body, &bodyJson)

	return &Input{
		Method:   r.Method,
		Path:     r.URL.Path,
		Headers:  r.Header,
		BodyJson: bodyJson,
	}
}

func (m *CaddyOpaMiddleware) Evaluate(input *Input) *Output {
	ctx := context.TODO()

	query, err := rego.New(
		rego.Query("allow = data.caddy.authz.allow; status_code = data.caddy.authz.status_code; message = data.caddy.authz.message"),
		rego.Module("caddy.opa_policy", m.Policy),
	).PrepareForEval(ctx)

	if err != nil {
		return &Output{
			Allow:      false,
			StatusCode: 500,
			Message:    "Error preparing rego query",
		}
	}

	inputMap := map[string]interface{}{
		"method":    input.Method,
		"path":      input.Path,
		"headers":   input.Headers,
		"body_json": input.BodyJson,
	}

	results, err := query.Eval(ctx, rego.EvalInput(inputMap))

	if err != nil {
		return &Output{
			Allow:      false,
			StatusCode: 500,
			Message:    "Error evaluating rego query",
		}
	}

	var allow bool
	var statusCode int
	var message string

	if val, ok := results[0].Bindings["allow"].(bool); ok {
		allow = val
	} else {
		allow = false
	}

	if val, ok := results[0].Bindings["status_code"].(int); ok {
		statusCode = val
	} else {
		statusCode = 403
	}

	if val, ok := results[0].Bindings["message"].(string); ok {
		message = val
	} else {
		message = "Unauthorized"
	}

	return &Output{
		Allow:      allow,
		StatusCode: statusCode,
		Message:    message,
	}
}

func (m CaddyOpaMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.logger.Info("CaddyOpaMiddleware: ServeHTTP")
	output := m.Evaluate(NewInputFromRequest(r))
	if !output.Allow {
		w.WriteHeader(output.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		jsonResponse := map[string]string{"message": output.Message}
		json.NewEncoder(w).Encode(jsonResponse)
		return nil
	}

	return next.ServeHTTP(w, r)
}

func (m *CaddyOpaMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var policy string
	for d.Next() {
		if !d.Args(&policy) {
			return d.ArgErr()
		}
	}
	m.Policy = policy
	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyOpaMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddyfile.Unmarshaler       = (*CaddyOpaMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyOpaMiddleware)(nil)
)
