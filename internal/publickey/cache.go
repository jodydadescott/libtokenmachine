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

package publickey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jodydadescott/libtokenmachine"
	"go.uber.org/zap"
)

const (
	defaultCacheRefreshInterval = time.Duration(5) * time.Minute
	defaultIdleConnections      = 4
	defaultRequestTimeout       = time.Duration(60) * time.Second
	defaultKeyLifetime          = 86400
)

// Config The config
type Config struct {
	CacheRefreshInterval, RequestTimeout time.Duration
	IdleConnections                      int
}

// Cache ...
type Cache struct {
	httpClient *http.Client
	mutex      sync.RWMutex
	internal   map[string]*PublicKey
	closed     chan struct{}
	ticker     *time.Ticker
	wg         sync.WaitGroup
}

// Build Returns a new Token Cache
func (config *Config) Build() (*Cache, error) {

	zap.L().Debug("Starting")

	cacheRefreshInterval := defaultCacheRefreshInterval
	requestTimeout := defaultRequestTimeout
	idleConnections := defaultIdleConnections

	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
	}

	if config.RequestTimeout > 0 {
		requestTimeout = config.RequestTimeout
	}

	if config.IdleConnections > 0 {
		idleConnections = config.IdleConnections
	}

	t := &Cache{
		internal: make(map[string]*PublicKey),
		closed:   make(chan struct{}),
		ticker:   time.NewTicker(cacheRefreshInterval),
		wg:       sync.WaitGroup{},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: idleConnections,
			},
			Timeout: requestTimeout,
		},
	}

	go t.run()
	return t, nil

}

func (t *Cache) run() {
	t.wg.Add(1)
	for {
		select {
		case <-t.closed:
			t.wg.Done()
			return
		case <-t.ticker.C:
			t.cleanup()

		}
	}
}

func (t *Cache) cleanup() {

	zap.L().Debug("Running cleanup")

	var removes []string
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, e := range t.internal {

		if time.Now().Unix() > e.Exp {
			removes = append(removes, key)
			zap.L().Info(fmt.Sprintf("Ejecting->%s", e.JSON()))
		} else {
			zap.L().Debug(fmt.Sprintf("Preserving->%s", e.JSON()))
		}
	}

	if len(removes) > 0 {
		for _, key := range removes {
			delete(t.internal, key)
		}
	}

	zap.L().Debug("Cleanup completed")

}

// GetKey Returns PublicKey from cache if found. If not gets PublicKey from
// validated issuer, stores in cache and returns copy
func (t *Cache) GetKey(iss, kid string) (*PublicKey, error) {

	key := iss + ":" + kid

	t.mutex.RLock()

	publicKey, exist := t.internal[key]
	if exist {
		t.mutex.RUnlock()
		return publicKey.Copy(), nil
	}

	t.mutex.RUnlock()

	t.mutex.Lock()
	defer t.mutex.Unlock()

	publicKey, exist = t.internal[key]
	if exist {
		return publicKey.Copy(), nil
	}

	openIDConfiguration, err := t.getOpenIDConfiguration(iss)
	if err != nil {
		return nil, err
	}

	// This is ugly. Could result in many errors logged when one will suffice
	for _, config := range *openIDConfiguration {
		if strings.HasPrefix(config.JwksURI, "https://") {
			jwks, err := t.getJWKs(config.JwksURI)
			if err == nil {
				for _, jwk := range jwks.Keys {
					if jwk.Kid == kid {
						publicKey, err := newKey(&jwk)
						if err == nil {
							publicKey.Iss = iss

							t.internal[key] = publicKey

							zap.L().Debug(fmt.Sprintf("key for iss %s and kid %s created and added to cache", iss, kid))
							// Export function; return copy
							return publicKey.Copy(), nil
						}
						zap.L().Error(err.Error())
					}
				}
			} else {
				zap.L().Error(err.Error())
			}
		} else {
			zap.L().Debug(fmt.Sprintf("JWKS URL %s malformed", config.JwksURI))
		}

	}

	return nil, libtokenmachine.ErrNotFound
}

func (t *Cache) getOpenIDConfiguration(fqdn string) (*openIDConfiguration, error) {

	resp, err := t.httpClient.Get(fqdn)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return openIDConfigurationFromJSON(b)
}

func (t *Cache) getJWKs(fqdn string) (*jwks, error) {

	resp, err := t.httpClient.Get(fqdn)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result jwks
	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

type openIDConfiguration []struct {
	Issuer                                    string   `json:"issuer,omitempty"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                             string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint                      string   `json:"registration_endpoint,omitempty"`
	JwksURI                                   string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported                    []string `json:"response_types_supported,omitempty,omitempty"`
	ResponseModesSupported                    []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                       []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                     []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                           []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported,omitempty"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpoint                        string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint,omitempty"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported,omitempty"`
}

func openIDConfigurationFromJSON(b []byte) (*openIDConfiguration, error) {
	var t openIDConfiguration
	err := json.Unmarshal(b, &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

type jwk struct {
	Kty string `json:"kty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	E   string `json:"e,omitempty"`
	N   string `json:"n,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (t *jwk) json() string {
	e, err := json.Marshal(t)
	if err != nil {
		panic(err.Error())
	}
	return string(e)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// JSON ...
func (t *jwks) json() string {
	e, err := json.Marshal(t)
	if err != nil {
		panic(err.Error())
	}
	return string(e)
}

func newKey(jwk *jwk) (*PublicKey, error) {

	if jwk.Kty == "" {
		return nil, fmt.Errorf("Kty is empty")
	}

	switch jwk.Kty {
	case "EC":
		return newKeyEC(jwk)
	case "RSA":
		return nil, fmt.Errorf("Not implemented")
	}

	return nil, fmt.Errorf("jwk kty type %s not supported", jwk.Kty)
}

func newKeyEC(jwk *jwk) (*PublicKey, error) {

	var curve elliptic.Curve

	switch jwk.Alg {

	case "ES224":
		curve = elliptic.P224()
	case "ES256":
		curve = elliptic.P256()
	case "ES384":
		curve = elliptic.P384()
	case "ES521":
		curve = elliptic.P521()

	default:
		return nil, fmt.Errorf("Curve %s not supported", jwk.Alg)
	}

	byteX, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	byteY, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		EcdsaPublicKey: &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(byteX),
			Y:     new(big.Int).SetBytes(byteY),
		},
		Exp: time.Now().Unix() + int64(defaultKeyLifetime),
		Kid: jwk.Kid,
		Kty: jwk.Kty,
	}, nil

}

// Shutdown Cache
func (t *Cache) Shutdown() {
	zap.L().Debug("Stopping")
	close(t.closed)
	t.wg.Wait()
}
