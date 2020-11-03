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
	"regexp"
	"time"
)

const (
	defaultCacheRefreshInterval = time.Duration(30) * time.Second

	keytabDefaultTickRate = time.Duration(10) * time.Second
	keytabDefaultLifetime = time.Duration(5) * time.Minute
	keytabPasswordCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@!"

	nonceCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nonceDefaultLifetime = time.Duration(60) * time.Second

	publicKeyDefaultIdleConnections = 4
	publicKeyDefaultRequestTimeout  = time.Duration(60) * time.Second
	publicKeyDefaultKeyLifetime     = 86400

	secretDefaultLifetime = time.Duration(12) * time.Hour
	secretCharset         = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@!"
)

var (
	keytabRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)
