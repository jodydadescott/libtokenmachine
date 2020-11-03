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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jodydadescott/libtokenmachine"
)

// PubKeyDummyCache ...
type PubKeyDummyCache struct {
	mutex    sync.Mutex
	internal map[string]*PublicKey
}

func newDummyPublicKeyCache() *PubKeyDummyCache {
	return &PubKeyDummyCache{
		internal: make(map[string]*PublicKey),
	}
}

// PutKey Puts key
func (t *PubKeyDummyCache) PutKey(key *PublicKey) error {

	if key.Iss == "" {
		return fmt.Errorf("Missing Issuer (iss)")
	}

	if key.Kid == "" {
		return fmt.Errorf("Missing Kid (kid)")
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.internal[key.Iss+":"+key.Kid] = key
	return nil
}

// GetKey Returns PublicKey from cache if found. If not gets PublicKey from
// validated issuer, stores in cache and returns copy
func (t *PubKeyDummyCache) GetKey(iss, kid string) (*PublicKey, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key, exist := t.internal[iss+":"+kid]
	if exist {
		return key, nil
	}

	return nil, libtokenmachine.ErrNotFound
}

func TestToken1(t *testing.T) {

	now := time.Now().Unix()

	// We generate a couple private keys and store their public key counterparts in a new Public Key Cache.
	// Then we create a new Token cache and provide it with the just created PublicKey cache. This allows
	// us to provide the matching public key for testing without the need to query external web servers.

	privateKeyA, publicKeyA, err := generateKeypair("https://issuer-a", "x", now+3600)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	privateKeyB, publicKeyB, err := generateKeypair("https://issuer-b", "x", now+3600)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	junkKey, _, err := generateKeypair("https://issuer-a", "x", now+3600)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	publicKeyCache := newDummyPublicKeyCache()
	config := &TokenConfig{}
	tokenCache, _ := config.Build(publicKeyCache)

	publicKeyCache.PutKey(publicKeyA)
	publicKeyCache.PutKey(publicKeyB)

	validTokenSignedByIssuerA, err := newToken("https://issuer-a", "x", now+600, privateKeyA)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	validTokenSignedByIssuerB, err := newToken("https://issuer-b", "x", now+600, privateKeyB)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	expiredTokenSignedByIssuerA, err := newToken("https://issuer-a", "x", now-600, privateKeyA)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	expiredTokenSignedByIssuerB, err := newToken("https://issuer-b", "x", now-600, privateKeyB)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	invalidTokenClaimingIssuerA, err := newToken("https://issuer-a", "x", now+600, junkKey)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	tokenFromMissingIssuer, err := newToken("https://does-not-exist", "x", now+600, junkKey)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	// Err NOT expected
	_, err = tokenCache.ParseToken(validTokenSignedByIssuerA)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Err NOT expected
	_, err = tokenCache.ParseToken(validTokenSignedByIssuerB)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Err expected
	_, err = tokenCache.ParseToken(expiredTokenSignedByIssuerA)
	if err != libtokenmachine.ErrExpired {
		t.Fatalf("Expected ErrExpired")
	}

	// Err expected
	_, err = tokenCache.ParseToken(expiredTokenSignedByIssuerB)
	if err != libtokenmachine.ErrExpired {
		t.Fatalf("Expected ErrExpired")
	}

	// Err expected
	_, err = tokenCache.ParseToken(invalidTokenClaimingIssuerA)
	if err != libtokenmachine.ErrTokenInvalid {
		t.Fatalf("Expected ErrTokenInvalid")
	}

	_, err = tokenCache.ParseToken(tokenFromMissingIssuer)
	if err != libtokenmachine.ErrTokenInvalid {
		t.Fatalf("Expected ErrTokenInvalid")
	}

}

func newToken(iss, kid string, exp int64, key *ecdsa.PrivateKey) (string, error) {

	claims := &jwt.StandardClaims{
		ExpiresAt: exp,
		Issuer:    iss,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func generateKeypair(iss, kid string, exp int64) (*ecdsa.PrivateKey, *PublicKey, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	publicKey := &PublicKey{
		EcdsaPublicKey: privateKey.Public().(*ecdsa.PublicKey),
		Iss:            iss,
		Kid:            kid,
		Kty:            "EC",
		Exp:            exp,
	}

	return privateKey, publicKey, nil
}
