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
	"testing"
	"time"
)

func Test1(t *testing.T) {

	var err error

	config := &NonceConfig{
		Lifetime: time.Duration(4) * time.Second,
	}

	nonces, err := config.Build()

	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	nonce1, _ := nonces.NewNonce()
	nonce2, _ := nonces.NewNonce()
	nonce3, _ := nonces.NewNonce()

	// TODO This must be rewritten

	if nonce1.Value == nonce2.Value {
		t.Fatalf("Unexpected")
	}

	if nonce1.Value == nonce3.Value {
		t.Fatalf("Unexpected")
	}

	if nonce2.Value == nonce3.Value {
		t.Fatalf("Unexpected")
	}

	nonces.Shutdown()

}
