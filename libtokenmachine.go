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

	"github.com/jodydadescott/libtokenmachine/core"
	"github.com/jodydadescott/libtokenmachine/internal"
)

// LibTokenMachine LibTokenMachine
type LibTokenMachine interface {
	Shutdown()
	GetNonce(ctx context.Context, tokenString string) (*core.Nonce, error)
	GetKeytab(ctx context.Context, tokenString, principal string) (*core.Keytab, error)
	GetSecret(ctx context.Context, tokenString, name string) (*core.Secret, error)
}

// NewInstance returns new instance of LibTokenMachine
func NewInstance(config *core.Config) (LibTokenMachine, error) {
	return internal.NewInstance(config)
}
