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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jodydadescott/libtokenmachine"
	"github.com/jodydadescott/libtokenmachine/internal/keytab"
	"github.com/jodydadescott/libtokenmachine/internal/nonce"
	"github.com/jodydadescott/libtokenmachine/internal/policy"
	"github.com/jodydadescott/libtokenmachine/internal/publickey"
	"github.com/jodydadescott/libtokenmachine/internal/secret"
	"github.com/jodydadescott/libtokenmachine/internal/token"
	"go.uber.org/zap"
)

// Cache ...
type Cache struct {
	publickey *publickey.Cache
	token     *token.Cache
	keytab    *keytab.Cache
	nonce     *nonce.Cache
	secret    *secret.Cache
	policy    *policy.Policy
}

func main() {
	fmt.Println("This is a library")
	os.Exit(2)
}

// NewInstance ...
func NewInstance(config *libtokenmachine.Config) (libtokenmachine.Cache, error) {

	zap.L().Info(fmt.Sprintf("Starting"))

	publickeyConfig := &publickey.Config{}
	tokenConfig := &token.Config{}
	keytabConfig := &keytab.Config{}
	nonceConfig := &nonce.Config{}
	secretConfig := &secret.Config{}
	policyConfig := &policy.Config{}

	if config.Policy != "" {
		policyConfig.Policy = config.Policy
	}

	if config.NonceLifetime > 0 {
		nonceConfig.Lifetime = config.NonceLifetime
	}

	if config.SecretSecrets != nil {
		secretConfig.Secrets = config.SecretSecrets
	}

	if config.SecretLifetime > 0 {
		secretConfig.Lifetime = config.SecretLifetime
	}

	if config.KeytabKeytabs != nil {
		keytabConfig.Keytabs = config.KeytabKeytabs
	}

	if config.KeytabLifetime > 0 {
		keytabConfig.Lifetime = config.KeytabLifetime
	}

	policy, err := policyConfig.Build()
	if err != nil {
		return nil, err
	}

	publickey, err := publickeyConfig.Build()
	if err != nil {
		return nil, err
	}

	token, err := tokenConfig.Build(publickey)
	if err != nil {
		return nil, err
	}

	keytab, err := keytabConfig.Build()
	if err != nil {
		return nil, err
	}

	nonce, err := nonceConfig.Build()
	if err != nil {
		return nil, err
	}

	secret, err := secretConfig.Build()
	if err != nil {
		return nil, err
	}

	return &Cache{
		publickey: publickey,
		token:     token,
		keytab:    keytab,
		nonce:     nonce,
		secret:    secret,
		policy:    policy,
	}, nil

}

// Shutdown shutdown
func (t *Cache) Shutdown() {
	zap.L().Debug("Stopping")
	t.secret.Shutdown()
	t.keytab.Shutdown()
	t.nonce.Shutdown()
	t.token.Shutdown()
	t.publickey.Shutdown()
}

// GetNonce returns Nonce if provided token is authorized
func (t *Cache) GetNonce(ctx context.Context, tokenString string) (*libtokenmachine.Nonce, error) {

	token, err := t.token.ParseToken(tokenString)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetNonce(tokenString=%s)->%s", tokenString, "Error:"+err.Error()))
		return nil, err
	}

	// Validate that token is allowed to pull nonce
	err = t.policy.AuthGetNonce(ctx, token.Claims)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetNonce(tokenString=%s)->%s", tokenString, "Error:"+err.Error()))
		return nil, err
	}

	nonce, err := t.nonce.NewNonce()
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetNonce(tokenString=%s)->%s", tokenString, "Error:"+err.Error()))
		return nil, err
	}

	zap.L().Debug(fmt.Sprintf("GetNonce(tokenString=%s)->%s", tokenString, "Granted"))
	return nonce, nil
}

// GetKeytab returns Keytab if provided token is authorized
func (t *Cache) GetKeytab(ctx context.Context, tokenString, principal string) (*libtokenmachine.Keytab, error) {

	token, err := t.token.ParseToken(tokenString)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetKeytab(tokenString=%s,principal=%s)->%s", tokenString, principal, "Error:"+err.Error()))
		return nil, err
	}

	nonce, err := t.nonce.GetNonce(token.Aud)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetKeytab(tokenString=%s,principal=%s)->%s", tokenString, principal, "Error:"+err.Error()))
		return nil, err
	}

	err = t.policy.AuthGetKeytab(ctx, token.Claims, nonce.Value, principal)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetKeytab(tokenString=%s,principal=%s)->%s", tokenString, principal, "Error:"+err.Error()))
		return nil, err
	}

	keytab, err := t.keytab.GetKeytab(principal)

	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetKeytab(tokenString=%s,principal=%s)->%s", tokenString, principal, "Error:"+err.Error()))
		return nil, err
	}

	zap.L().Debug(fmt.Sprintf("GetKeytab(tokenString=%s,principal=%s)->%s", tokenString, principal, "Granted"))
	return keytab, nil
}

// GetSecret returns Secret if provided token is authorized
func (t *Cache) GetSecret(ctx context.Context, tokenString, name string) (*libtokenmachine.Secret, error) {

	token, err := t.token.ParseToken(tokenString)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetSecret(tokenString=%s,name=%s)->%s", tokenString, name, "Error:"+err.Error()))
		return nil, err
	}

	nonce, err := t.nonce.GetNonce(token.Aud)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetSecret(tokenString=%s,principal=%s)->%s", tokenString, name, "Error:"+err.Error()))
		return nil, err
	}

	err = t.policy.AuthGetSecret(ctx, token.Claims, nonce.Value, name)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetSecret(tokenString=%s,name=%s)->%s", tokenString, name, "Error:"+err.Error()))
		return nil, err
	}

	secret, err := t.secret.GetSecret(name)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("GetSecret(tokenString=%s,name=%s)->%s", tokenString, name, "Error:"+err.Error()))
		return nil, err
	}

	zap.L().Debug(fmt.Sprintf("GetSecret(tokenString=%s,name=%s)->%s", tokenString, name, "Granted"))
	return secret, nil
}
