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

package core

import (
	"encoding/json"

	"github.com/jinzhu/copier"
)

// Nonce holds one time expiring secret
type Nonce struct {
	Exp   int64  `json:"exp,omitempty" yaml:"exp,omitempty"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// JSON Return JSON String representation
func (t *Nonce) JSON() string {
	j, _ := json.Marshal(t)
	return string(j)
}

// Copy return copy
func (t *Nonce) Copy() *Nonce {
	clone := &Nonce{}
	copier.Copy(&clone, &t)
	return clone
}
