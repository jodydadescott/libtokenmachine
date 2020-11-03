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

package internal

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/jodydadescott/libtokenmachine"
	"go.uber.org/zap"
)

// NonceConfig Config
type NonceConfig struct {
	CacheRefreshInterval, Lifetime time.Duration
}

// NonceCache Manages nonces. For our purposes a nonce is defined as a random
// string with an expiration time. Upon request a new nonce is generated
// and returned along with the expiration time to the caller. This allows
// the caller to hand the nonce to a remote party. The remote party can then
// present the nonce back in the future (before the expiration time is reached)
// and the nonce can be validated that it originated with us.
type NonceCache struct {
	mutex      sync.RWMutex
	internal   map[string]*libtokenmachine.Nonce
	closed     chan struct{}
	ticker     *time.Ticker
	wg         sync.WaitGroup
	seededRand *rand.Rand
	lifetime   time.Duration
}

// Build Returns a new Cache
func (config *NonceConfig) Build() (*NonceCache, error) {

	zap.L().Debug("Starting")

	cacheRefreshInterval := defaultCacheRefreshInterval
	lifetime := nonceDefaultLifetime

	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
	}

	if config.Lifetime > 0 {
		lifetime = config.Lifetime
	}

	t := &NonceCache{
		internal: make(map[string]*libtokenmachine.Nonce),
		closed:   make(chan struct{}),
		ticker:   time.NewTicker(cacheRefreshInterval),
		wg:       sync.WaitGroup{},
		lifetime: lifetime,
		seededRand: rand.New(
			rand.NewSource(time.Now().Unix())),
	}

	go t.run()
	return t, nil
}

func (t *NonceCache) run() {
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

func (t *NonceCache) cleanup() {

	zap.L().Debug("Running Nonce cleanup")

	var removes []string
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, e := range t.internal {
		if time.Now().Unix() > e.Exp {
			removes = append(removes, key)
			zap.L().Info(fmt.Sprintf("Ejecting Nonce->%s", e.JSON()))
		}
	}

	if len(removes) > 0 {
		for _, key := range removes {
			delete(t.internal, key)
		}
	}

	zap.L().Debug("Completed Nonce cleanup")
}

// NewNonce Returns a new nonce
func (t *NonceCache) NewNonce() (*libtokenmachine.Nonce, error) {

	b := make([]byte, 64)
	for i := range b {
		b[i] = nonceCharset[t.seededRand.Intn(len(nonceCharset))]
	}

	nonce := &libtokenmachine.Nonce{
		Exp:   time.Now().Unix() + int64(t.lifetime.Seconds()),
		Value: string(b),
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.internal[nonce.Value] = nonce

	// Func is exported. Return clone to untrusted outsiders
	return nonce, nil
}

// GetNonceValues returns slice of all valid nonce values
func (t *NonceCache) GetNonceValues() []string {

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	var nonces []string
	for _, nonce := range t.internal {
		if time.Now().Unix() < nonce.Exp {
			nonces = append(nonces, nonce.Value)
		}
	}

	return nonces
}

// Shutdown shutdowns the cache map
func (t *NonceCache) Shutdown() {
	zap.L().Debug("Stopping")
	close(t.closed)
	t.wg.Wait()
}
