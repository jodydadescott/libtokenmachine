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

package nonce

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/jodydadescott/libtokenmachine"
	"go.uber.org/zap"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	defaultCacheRefreshInterval = time.Duration(30) * time.Second
	defaultLifetime             = time.Duration(60) * time.Second
)

// Config Config
type Config struct {
	CacheRefreshInterval time.Duration
	Lifetime             int64
}

// Cache Manages nonces. For our purposes a nonce is defined as a random
// string with an expiration time. Upon request a new nonce is generated
// and returned along with the expiration time to the caller. This allows
// the caller to hand the nonce to a remote party. The remote party can then
// present the nonce back in the future (before the expiration time is reached)
// and the nonce can be validated that it originated with us.
type Cache struct {
	mutex      sync.RWMutex
	internal   map[string]*libtokenmachine.Nonce
	closed     chan struct{}
	ticker     *time.Ticker
	wg         sync.WaitGroup
	seededRand *rand.Rand
	lifetime   int64
}

// Build Returns a new Cache
func (config *Config) Build() (*Cache, error) {

	zap.L().Debug("Starting")

	cacheRefreshInterval := defaultCacheRefreshInterval
	lifetime := defaultLifetime

	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
	}

	if config.Lifetime > 0 {
		lifetime = time.Duration(config.Lifetime) * time.Second
	}

	t := &Cache{
		internal: make(map[string]*libtokenmachine.Nonce),
		closed:   make(chan struct{}),
		ticker:   time.NewTicker(cacheRefreshInterval),
		wg:       sync.WaitGroup{},
		lifetime: int64(lifetime),
		seededRand: rand.New(
			rand.NewSource(time.Now().Unix())),
	}

	go func() {
		t.wg.Add(1)
		for {
			select {
			case <-t.closed:
				t.wg.Done()
				return
			case <-t.ticker.C:
				t.processCache()

			}
		}
	}()

	return t, nil
}

func (t *Cache) processCache() {

	zap.L().Debug("Processing cache start")

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

	zap.L().Debug("Processing cache completed")

}

// NewNonce Returns a new nonce
func (t *Cache) NewNonce() (*libtokenmachine.Nonce, error) {

	b := make([]byte, 64)
	for i := range b {
		b[i] = charset[t.seededRand.Intn(len(charset))]
	}

	nonce := &libtokenmachine.Nonce{
		Exp:   time.Now().Unix() + t.lifetime,
		Value: string(b),
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.internal[nonce.Value] = nonce

	// Func is exported. Return clone to untrusted outsiders
	return nonce.Copy(), nil
}

// GetNonce returns nonce if found and not expired
func (t *Cache) GetNonce(key string) (*libtokenmachine.Nonce, error) {

	if key == "" {
		zap.L().Warn("request for empty nonce")
		return nil, libtokenmachine.ErrNotFound
	}

	nonce, exist := t.internal[key]
	if exist {
		if time.Now().Unix() > nonce.Exp {
			zap.L().Debug(fmt.Sprintf("Nonce expired; nonce key:%s", key))
			return nil, libtokenmachine.ErrExpired
		}
		// Func is exported. Return clone to untrusted outsiders
		zap.L().Debug(fmt.Sprintf("Nonce found and not expired; nonce key:%s", key))
		return nonce.Copy(), nil
	}

	zap.L().Debug(fmt.Sprintf("Nonce not found; nonce key:%s", key))
	return nil, libtokenmachine.ErrNotFound

}

// Shutdown shutdowns the cache map
func (t *Cache) Shutdown() {
	zap.L().Debug("Stopping")
	close(t.closed)
	t.wg.Wait()
}
