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

import (
	"context"
)

// Cache ...
type Cache interface {
	Shutdown()
	GetNonce(ctx context.Context, tokenString string) (*Nonce, error)
	GetKeytab(ctx context.Context, tokenString, principal string) (*Keytab, error)
	GetSecret(ctx context.Context, tokenString, name string) (*Secret, error)
}
