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
	"errors"
)

var (
	// ErrNotFound Entity not found
	ErrNotFound error = errors.New("Entity not found")

	// ErrExpired Entity expired
	ErrExpired error = errors.New("Entity expired")

	// ErrDenied Denied
	ErrDenied error = errors.New("Denied")

	// ErrServerFail Policy engine returned unexpected error
	ErrServerFail error = errors.New("Internal server error")

	// ErrTokenInvalid Failed
	ErrTokenInvalid error = errors.New("Token is invalid")
)
