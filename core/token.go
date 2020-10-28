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
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/jinzhu/copier"
)

// Token OAUTH/OIDC Token
type Token struct {
	Alg    string                 `json:"alg,omitempty" yaml:"alg,omitempty"`
	Kid    string                 `json:"kid,omitempty" yaml:"kid,omitempty"`
	Typ    string                 `json:"typ,omitempty" yaml:"typ,omitempty"`
	Iss    string                 `json:"iss,omitempty" yaml:"iss,omitempty"`
	Exp    int64                  `json:"exp,omitempty" yaml:"exp,omitempty"`
	Aud    string                 `json:"aud,omitempty" yaml:"aud,omitempty"`
	Claims map[string]interface{} `json:"claims,omitempty" yaml:"claims,omitempty"`
}

// JSON Return JSON String representation
func (t *Token) JSON() string {
	j, _ := json.Marshal(t)
	return string(j)
}

// Copy return copy
func (t *Token) Copy() *Token {
	c := &Token{}
	copier.Copy(&c, &t)
	return c
}

// ParseToken returns token from base64 encoded string. It does NOT validate
// the token.
func ParseToken(tokenString string) (*Token, error) {

	// We are intentionally not using the jwt-go library. We will use the jwt-go library to validate

	if len(tokenString) < 12 {
		return nil, ErrTokenInvalid
	}

	tokenStringSlice := strings.Split(tokenString, ".")

	if len(tokenStringSlice) != 3 {
		return nil, ErrTokenInvalid
	}

	headerJSONString, err := base64.RawURLEncoding.DecodeString(tokenStringSlice[0])
	if err != nil {
		return nil, err
	}

	payloadJSONString, err := base64.RawURLEncoding.DecodeString(tokenStringSlice[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}

	err = json.Unmarshal(payloadJSONString, &payload)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	var header map[string]interface{}

	err = json.Unmarshal(headerJSONString, &header)
	if err != nil {
		return nil, err
	}

	token := &Token{
		Claims: payload,
	}

	for k, v := range payload {

		if k == "iss" {
			token.Iss, _ = v.(string)
		}

		if k == "exp" {
			floatValue, _ := v.(float64)
			token.Exp = int64(floatValue)
		}

		if k == "aud" {
			token.Aud, _ = v.(string)
		}

	}

	for k, v := range header {

		if k == "alg" {
			token.Alg, _ = v.(string)
		}

		if k == "kid" {
			token.Kid, _ = v.(string)
		}

		if k == "typ" {
			token.Typ, _ = v.(string)
		}

	}

	return token, nil
}
