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

package token

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jodydadescott/libtokenmachine"
	"github.com/jodydadescott/libtokenmachine/internal/publickey"
	"go.uber.org/zap"
)

const (
	defaultCacheRefreshInterval = time.Duration(5) * time.Minute
)

// PublicKeyCache PublicKeyCache
type PublicKeyCache interface {
	GetKey(iss, kid string) (*publickey.PublicKey, error)
}

// Config The config
type Config struct {
	CacheRefreshInterval time.Duration
}

// Cache Parses and verifies tokens by fetching public keys from the token issuer and caching
// public keys for future use. Tokens that are verified are also stored in the cache for
// quicker validation in the future. Replay attack is also provided by a Nonce implementation.
// The nonce implementation works by generating random strings that may be fetched by a
// token bearer. The bearer should use the nonce to get a new token from their token provider
// with the audience (aud) field set to the nonce value. When then token is parsed
type Cache struct {
	tokenMapMutex       sync.RWMutex
	tokenMap            map[string]*libtokenmachine.Token
	closed              chan struct{}
	ticker              *time.Ticker
	wg                  sync.WaitGroup
	seededRand          *rand.Rand
	permitPublicKeyHTTP bool
	publicKeyCache      PublicKeyCache
}

// Build returns new instance of cache from config
func (config *Config) Build(publicKeyCache PublicKeyCache) (*Cache, error) {

	zap.L().Debug("Starting")

	cacheRefreshInterval := defaultCacheRefreshInterval

	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
	}

	t := &Cache{
		tokenMap:       make(map[string]*libtokenmachine.Token),
		closed:         make(chan struct{}),
		ticker:         time.NewTicker(cacheRefreshInterval),
		wg:             sync.WaitGroup{},
		publicKeyCache: publicKeyCache,
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
			zap.L().Debug("Processing cache start")
			t.processTokenCache()
			zap.L().Debug("Processing cache completed")
		}
	}
}

func (t *Cache) mapGetToken(key string) *libtokenmachine.Token {
	t.tokenMapMutex.RLock()
	defer t.tokenMapMutex.RUnlock()
	return t.tokenMap[key]
}

func (t *Cache) mapPutToken(key string, entity *libtokenmachine.Token) {
	t.tokenMapMutex.Lock()
	defer t.tokenMapMutex.Unlock()
	t.tokenMap[key] = entity
}

// ParseToken ...
func (t *Cache) ParseToken(tokenString string) (*libtokenmachine.Token, error) {

	if tokenString == "" {
		zap.L().Debug("tokenString is empty")
		return nil, libtokenmachine.ErrTokenInvalid
	}

	token := t.mapGetToken(tokenString)

	if token != nil {
		zap.L().Debug(fmt.Sprintf("Token %s found in cache", tokenString))

		if token.Exp > time.Now().Unix() {
			zap.L().Debug(fmt.Sprintf("Token %s is expired", tokenString))
			return nil, libtokenmachine.ErrExpired
		}

		return token.Copy(), nil
	}

	var err error
	token, err = libtokenmachine.ParseToken(tokenString)
	if err != nil {
		zap.L().Debug(fmt.Sprintf("Unable to parse token %s", tokenString))
		return nil, err
	}

	zap.L().Debug(fmt.Sprintf("Token not found in cache; token=%s", tokenString))

	if token.Alg == "" {
		zap.L().Debug(fmt.Sprintf("Token %s is missing required field alg", tokenString))
		return nil, libtokenmachine.ErrTokenInvalid
	}

	if token.Kid == "" {
		zap.L().Debug(fmt.Sprintf("Token %s is missing required field kid", tokenString))
		return nil, libtokenmachine.ErrTokenInvalid
	}

	if token.Typ == "" {
		zap.L().Debug(fmt.Sprintf("Token %s is missing required field typ", tokenString))
		return nil, libtokenmachine.ErrTokenInvalid
	}

	if token.Iss == "" {
		zap.L().Debug(fmt.Sprintf("Token %s is missing required field iss", tokenString))
		return nil, libtokenmachine.ErrTokenInvalid
	}

	if !strings.HasPrefix(token.Iss, "http") {
		zap.L().Debug(fmt.Sprintf("Token %s has field iss but value %s is not expected", tokenString, token.Iss))
		return nil, libtokenmachine.ErrTokenInvalid
	}

	if !t.permitPublicKeyHTTP {
		if !strings.HasPrefix(token.Iss, "https") {
			zap.L().Debug(fmt.Sprintf("Token %s has field iss but value %s is not permitted as https is required", tokenString, token.Iss))
			return nil, libtokenmachine.ErrTokenInvalid
		}
	}

	_, err = jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {

		// SigningMethodRSA

		publicKey, err := t.publicKeyCache.GetKey(token.Iss, token.Kid)
		if err != nil {
			return nil, err
		}

		if publicKey.Kty == "" {
			return nil, fmt.Errorf("kty is empty. should be EC or RSA")
		}

		switch jwtToken.Method.(type) {
		case *jwt.SigningMethodECDSA:
			if publicKey.Kty != "EC" {
				return nil, fmt.Errorf("Expected value for kty is EC not %s", publicKey.Kty)
			}
			break
		case *jwt.SigningMethodRSA:
			if publicKey.Kty != "RSA" {
				return nil, fmt.Errorf("Expected value for kty is RSA not %s", publicKey.Kty)
			}
			break
		default:
			return nil, fmt.Errorf("Signing type %s unsupported", publicKey.Kty)
		}

		return publicKey.EcdsaPublicKey, nil

	})

	if err != nil {
		if err.Error() == "Token is expired" {
			// We will be the judge of that
		} else if err.Error() == "Token used before issued" {
			// Slight drift in clock. We will be the judge of that
		} else {
			zap.L().Debug(fmt.Sprintf("Unable to verify signature for token %s; error=%s", tokenString, err.Error()))
			return nil, libtokenmachine.ErrTokenInvalid
		}
	}

	if time.Now().Unix() > token.Exp {
		zap.L().Debug(fmt.Sprintf("Token %s is expired", tokenString))
		return nil, libtokenmachine.ErrExpired
	}

	t.mapPutToken(tokenString, token)
	zap.L().Debug(fmt.Sprintf("Token %s added to cache", tokenString))
	return token.Copy(), nil
}

func (t *Cache) processTokenCache() {

	zap.L().Debug("Processing Token cache")

	var removes []string
	t.tokenMapMutex.Lock()
	defer t.tokenMapMutex.Unlock()

	for key, e := range t.tokenMap {

		if time.Now().Unix() > e.Exp {
			removes = append(removes, key)
			zap.L().Info(fmt.Sprintf("Ejecting->%s", e.JSON()))
		} else {
			zap.L().Debug(fmt.Sprintf("Preserving->%s", e.JSON()))
		}
	}

	if len(removes) > 0 {
		for _, key := range removes {
			delete(t.tokenMap, key)
		}
	}

	zap.L().Debug("Processing Token cache completed")

}

// Shutdown Cache
func (t *Cache) Shutdown() {
	zap.L().Debug("Stopping")
	close(t.closed)
	t.wg.Wait()
}
