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

package secret

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sync"
	"time"

	"github.com/jodydadescott/libtokenmachine"
	"github.com/jodydadescott/libtokenmachine/internal/util"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

const (
	defaultLifetime = time.Duration(12) * time.Hour

	secretCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@!"
)

// Config Config
type Config struct {
	Secrets  []*libtokenmachine.Secret
	Lifetime time.Duration
}

type secretWrapper struct {
	name, seed string
	timePeriod *util.TimePeriod
	mutex      sync.Mutex
}

// Cache Manages shared secrets
type Cache struct {
	mutex    sync.RWMutex
	internal map[string]*secretWrapper
	lifetime time.Duration
}

// Build Returns a new Cache
func (config *Config) Build() (*Cache, error) {

	zap.L().Debug("Starting")

	lifetime := defaultLifetime

	if config.Lifetime > 0 {
		lifetime = config.Lifetime
	}

	if lifetime < time.Minute {
		return nil, fmt.Errorf("Default lifetime must be one minute or greater")
	}

	t := &Cache{
		internal: make(map[string]*secretWrapper),
		lifetime: lifetime,
	}

	err := t.loadSecrets(config.Secrets)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Cache) loadSecrets(secrets []*libtokenmachine.Secret) error {

	if secrets == nil || len(secrets) <= 0 {
		zap.L().Warn("No secrets to load?")
		return nil
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()
	for _, secret := range secrets {
		err := t.addSecret(secret)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Cache) addSecret(secret *libtokenmachine.Secret) error {

	// Must have map locked!

	if secret == nil {
		return fmt.Errorf("secret is nil")
	}

	if secret.Name == "" {
		return fmt.Errorf("Name is required")
	}

	if secret.Seed == "" {
		return fmt.Errorf("Seed is required")
	}

	lifetime := t.lifetime

	if secret.Lifetime > 0 {
		lifetime = time.Duration(secret.Lifetime) * time.Second
	}

	seed := base32.StdEncoding.EncodeToString([]byte(secret.Seed))

	t.internal[secret.Name] = &secretWrapper{
		name:       secret.Name,
		timePeriod: util.NewPeriod(lifetime),
		seed:       seed,
	}

	return nil
}

// GetSecret Returns secret if found and authorized
func (t *Cache) GetSecret(name string) (*libtokenmachine.Secret, error) {

	if name == "" {
		zap.L().Debug("name is empty")
		return nil, libtokenmachine.ErrNotFound
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	var ok bool
	var wrapper *secretWrapper

	wrapper, ok = t.internal[name]

	if !ok {
		zap.L().Debug(fmt.Sprintf("Secret with name %s not found", name))
		return nil, libtokenmachine.ErrNotFound
	}

	wrapper.mutex.Lock()
	defer wrapper.mutex.Unlock()

	now := getTime()

	var err error
	var nowsecret string
	var nextsecret string

	nowPeriod := wrapper.timePeriod.From(now)
	nextPeriod := nowPeriod.Next()

	nowsecret, err = wrapper.getSecretString(nowPeriod.Time())
	if err != nil {
		return nil, err
	}

	result := &libtokenmachine.Secret{
		Exp:    nowPeriod.Time().Unix(),
		Secret: nowsecret,
	}

	if nowPeriod.HalfLife(now) {
		zap.L().Debug("HalfLife has been reached, adding next secret to set")

		nextsecret, err = wrapper.getSecretString(nextPeriod.Time())
		if err == nil {
			result.NextExp = nowPeriod.Next().Time().Unix()
			result.NextSecret = nextsecret
		} else {
			zap.L().Error(fmt.Sprintf("Unexpected error %s", err))
		}
	} else {
		zap.L().Debug("HalfLife has not been reached")
	}

	return result, nil
}

func (t *secretWrapper) getSecretString(now time.Time) (string, error) {

	// The OTP will only be 8 random digits. We combine this with the original
	// seed and get a hash. Then we convert the hex hash to a string based on
	// our defined charset

	otp, err := totp.GenerateCodeCustom(t.seed, now, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})

	if err != nil {
		zap.L().Error(fmt.Sprintf("Unexpected error %s", err))
		return "", libtokenmachine.ErrServerFail
	}

	hash := sha256.Sum256([]byte(otp + t.seed))

	b := make([]byte, 28)
	for i := range b {
		b[i] = getChar(hash[i])
	}

	return string(b), nil
}

func getChar(b byte) byte {
	bint := int(b)
	charsetlen := len(secretCharset)
	if int(b) < charsetlen {
		return secretCharset[bint]
	}
	_, r := bint/charsetlen, bint%charsetlen
	return secretCharset[r]
}

func int31n(n int, input int64) int32 {
	v := uint32(input >> 31)
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < uint32(n) {
		thresh := uint32(-n) % uint32(n)
		for low < thresh {
			v = uint32(input >> 31)
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return int32(prod >> 32)
}

func getTime() time.Time {
	// If running multiple instance the time must be the same so we statically use UTC
	return time.Now().In(time.UTC)
}

// Shutdown Server
func (t *Cache) Shutdown() {
	zap.L().Debug("Stopping")
}
