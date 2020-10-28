/*
Copyright © 2020 Jody Scott <jody@thescottsweb.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"context"
	"fmt"

	"github.com/jodydadescott/libtokenmachine"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"
)

// Config config
type Config struct {
	Policy string
}

// Policy ...
type Policy struct {
	query rego.PreparedEvalQuery
}

// Build ...
func (config *Config) Build() (*Policy, error) {

	if config.Policy == "" {
		return nil, fmt.Errorf("Policy is required")
	}

	ctx := context.Background()

	query, err := rego.New(
		rego.Query("auth_get_nonce = data.main.auth_get_nonce; auth_get_keytab = data.main.auth_get_keytab; auth_get_secret = data.main.auth_get_secret"),
		rego.Module("kerberos.rego", config.Policy),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	return &Policy{
		query: query,
	}, nil
}

// AuthGetNonce Auth that claims are allowed to get nonce
func (t *Policy) AuthGetNonce(ctx context.Context, claims map[string]interface{}) error {

	input := &Input{
		Claims: claims,
	}

	results, err := t.query.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; err->%s", err))
		return libtokenmachine.ErrServerFail
	}

	if len(results) == 0 {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; results are empty"))
		return libtokenmachine.ErrServerFail
	}

	if auth, ok := results[0].Bindings["auth_get_nonce"].(bool); ok {
		if auth {
			return nil
		}
		return libtokenmachine.ErrDenied
	}

	zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; unexpected result type"))
	return libtokenmachine.ErrServerFail
}

// AuthGetKeytab Auth that claims, nonce and principals are allowed to get requested keytab
func (t *Policy) AuthGetKeytab(ctx context.Context, claims map[string]interface{}, nonce, principal string) error {

	input := &Input{
		Claims:    claims,
		Nonce:     nonce,
		Principal: principal,
	}

	results, err := t.query.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; err->%s", err))
		return libtokenmachine.ErrServerFail
	}

	if len(results) == 0 {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; results are empty"))
		return libtokenmachine.ErrServerFail
	}

	if auth, ok := results[0].Bindings["auth_get_keytab"].(bool); ok {
		if auth {
			return nil
		}
		return libtokenmachine.ErrDenied
	}

	zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; unexpected result type"))
	return libtokenmachine.ErrServerFail
}

// AuthGetSecret Auth request for secret
func (t *Policy) AuthGetSecret(ctx context.Context, claims map[string]interface{}, nonce, name string) error {

	input := &Input{
		Claims: claims,
		Nonce:  nonce,
		Secret: name,
	}

	results, err := t.query.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; err->%s", err))
		return libtokenmachine.ErrServerFail
	}

	if len(results) == 0 {
		zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; results are empty"))
		return libtokenmachine.ErrServerFail
	}

	if auth, ok := results[0].Bindings["auth_get_secret"].(bool); ok {
		if auth {
			return nil
		}
		return libtokenmachine.ErrDenied
	}

	zap.L().Error(fmt.Sprintf("Unexpected error on Rego policy execution; unexpected result type"))
	return libtokenmachine.ErrServerFail
}
