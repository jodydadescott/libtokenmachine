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
	"context"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

var (
	examplePolicy = `
	package main

	default auth_get_nonce = false
	default auth_get_keytab = false
	default auth_get_secret = false
	
	auth_base {
	   # Match Issuer
	   input.claims.iss == "abc123"
	}
	
	auth_get_nonce {
	   auth_base
	}
	
	auth_nonce {
	   # The input contains a set of all of the current valid nonces. For our
	   # example here we expect the claim audience to have a nonce that will match
	   # one of tne entries in the nonces set.
	   input.nonces[_] == input.claims.aud
	}
	
	auth_get_keytab {
	   # The nonce must be validated and then the principal. This is done by splitting the
	   # principals in the claim service.keytab by the comma into a set and checking for
	   # match with requested principal
	   auth_base
	   auth_nonce
	   split(input.claims.service.keytab,",")[_] == input.principal
	}
	
	auth_get_secret {
	   auth_base
	   auth_nonce
	   input.claims.service.secrets[_] == input.secret
	}
`

	exampleInput = `
{
	"alg": "EC",
	"kid": "donut",
	"iss": "abc123",
	"exp": 1599844897,
	"aud": "daisy",
	"service": {
	  "keytab": "user1@example.com,user2@example.com",
	  "secrets": ["secret1"]
	}
  }
`
)

func Test1(t *testing.T) {

	var claims map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal([]byte(exampleInput), &claims)

	ctx := context.Background()

	query, err := rego.New(
		rego.Query("auth_get_nonce = data.main.auth_get_nonce; auth_get_keytab = data.main.auth_get_keytab; auth_get_secret = data.main.auth_get_secret"),
		rego.Module("kerberos.rego", examplePolicy),
	).PrepareForEval(ctx)

	if err != nil {
		t.Errorf("Unexpected error:%s", err)
		return
	}

	policy := &Policy{
		query: query,
	}

	if err != nil {
		t.Errorf("Unexpected error:%s", err)
	}

	err = policy.AuthGetNonce(ctx, claims)
	if err != nil {
		t.Errorf("Unexpected")
	}

	nonces := []string{"none"}

	err = policy.AuthGetKeytab(ctx, claims, nonces, "user1@example.com")
	if err == nil {
		t.Errorf("Unexpected")
	}

	nonces = append(nonces, "daisy")

	err = policy.AuthGetKeytab(ctx, claims, nonces, "user1@example.com")
	if err != nil {
		t.Errorf("Unexpected")
	}

	err = policy.AuthGetSecret(ctx, claims, nonces, "secret1")
	if err != nil {
		t.Errorf("Unexpected")
	}

	err = policy.AuthGetSecret(ctx, claims, nonces, "nosecret")
	if err == nil {
		t.Errorf("Unexpected")
	}

}
