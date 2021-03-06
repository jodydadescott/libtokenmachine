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

package libtokenmachine

import "time"

// Config ...
type Config struct {
	Policy               string          // OPA/Rego policy that will be used to authorize request
	NonceLifetime        time.Duration   // Lifetime of Nonce (default is 1 minute)
	SecretSecrets        []*SharedSecret // Secrets that will be served
	KeytabKeytabs        []*Keytab       // Keytabs that will be served
	KeytabLifetime       time.Duration   // Default lifetime
	SharedSecretLifetime time.Duration   // Default lifetime
}
