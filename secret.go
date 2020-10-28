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
	"encoding/json"

	"github.com/jinzhu/copier"
)

// Secret Holds a secret. Both state and config.
type Secret struct {
	Name       string `json:"name,omitempty" yaml:"name,omitempty"`
	Seed       string `json:"seed,omitempty" yaml:"seed,omitempty"`
	Lifetime   int64  `json:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Exp        int64  `json:"exp,omitempty" yaml:"exp,omitempty"`
	Secret     string `json:"secret,omitempty" yaml:"secret,omitempty"`
	NextExp    int64  `json:"nextExp,omitempty" yaml:"nextExp,omitempty"`
	NextSecret string `json:"nextSecret,omitempty" yaml:"nextSecret,omitempty"`
}

// JSON Return JSON String representation
func (t *Secret) JSON() string {
	j, _ := json.Marshal(t)
	return string(j)
}

// Clone return copy of entity
func (t *Secret) Clone() *Secret {
	clone := &Secret{}
	copier.Copy(&clone, &t)
	return clone
}
