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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/jodydadescott/libtokenmachine"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// KeytabConfig Config
type KeytabConfig struct {
	Keytabs  []*libtokenmachine.Keytab
	TickRate time.Duration
	Lifetime time.Duration
}

// KeytabCache holds and manages Kerberos Keytabs. Keytab files are generated using
// a password derived from the current time period and per Keytab seed. Keytabs
// are generated at the top of the period. It is possible to have multiple instance
// of this with no communication required between the instances and no conflict if the
// seed is configure the same and the clocks are synchronized from an accurate (or same)
// source.
type KeytabCache struct {
	closeTimer chan struct{}
	wg         sync.WaitGroup
	ticker     *time.Ticker
	mutex      sync.RWMutex
	internal   map[string]*keytabWrapper
	lifetime   time.Duration
	tickRate   time.Duration
}

type keytabWrapper struct {
	mutex                 sync.RWMutex
	nextUpdate            time.Time
	name, principal, seed string
	keytab                *libtokenmachine.Keytab
	err                   error
	timePeriod            *TimePeriod
}

// Build Returns new instance of Keytabs
func (config *KeytabConfig) Build() (*KeytabCache, error) {

	zap.L().Debug("Starting")

	tickRate := keytabDefaultTickRate
	lifetime := keytabDefaultLifetime

	if config.TickRate > 0 {
		tickRate = config.TickRate
	}

	if config.Lifetime > 0 {
		lifetime = config.Lifetime
	}

	if tickRate > lifetime {
		return nil, fmt.Errorf("Lifetime may not be less then the tickRate")
	}

	t := &KeytabCache{
		closeTimer: make(chan struct{}),
		wg:         sync.WaitGroup{},
		ticker:     time.NewTicker(time.Second),
		internal:   make(map[string]*keytabWrapper),
		lifetime:   lifetime,
		tickRate:   tickRate,
	}

	err := t.init(config)
	if err != nil {
		return nil, err
	}

	go t.run()
	return t, nil
}

func (t *KeytabCache) init(config *KeytabConfig) error {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, keytab := range config.Keytabs {

		if keytab.Name == "" {
			return fmt.Errorf("Keytab name is required")
		}

		if keytab.Principal == "" {
			return fmt.Errorf("Keytab %s is missing required principal", keytab.Name)
		}

		if len(keytab.Principal) < 3 && len(keytab.Principal) > 254 {
			if len(keytab.Principal) < 3 {
				return fmt.Errorf("Keytab %s principal %s is to short", keytab.Name, keytab.Principal)
			}
			return fmt.Errorf("Keytab %s principal %s is to long", keytab.Name, keytab.Principal)
		}

		if !keytabRegex.MatchString(keytab.Principal) {
			return fmt.Errorf("Keytab %s principal %s is invalid", keytab.Name, keytab.Name)
		}

		if keytab.Seed == "" {
			return fmt.Errorf("Keytab %s is missing required seed", keytab.Name)
		}

		seed := base32.StdEncoding.EncodeToString([]byte(keytab.Seed))

		lifetime := t.lifetime

		if keytab.Lifetime > 0 {
			lifetime = keytab.Lifetime
		}

		// Lifetime less then a minute requires to much resources and does not make much sense
		if t.tickRate > lifetime {
			return fmt.Errorf(fmt.Sprintf("Keytab %s lifetime of %s less then tickrate of %s", keytab.Name, lifetime, t.tickRate))
		}

		t.internal[keytab.Name] = &keytabWrapper{
			name:       keytab.Name,
			principal:  keytab.Principal,
			timePeriod: NewPeriod(lifetime),
			seed:       seed,
		}
		zap.L().Debug(fmt.Sprintf("Loaded Keytab %s with lifetime of %s", keytab.Name, lifetime))
	}

	return nil
}

func (t *KeytabCache) run() {

	t.wg.Add(1)

	// TimePeriod based on tick rate
	timeperiod := NewPeriod(t.tickRate)
	nowPeriod := timeperiod.From(getTime())
	nextPeriod := nowPeriod.Next()

	next := nextPeriod.Time()

	// On start create Keytabs with the top of the current period
	go t.firstRun(nowPeriod.Time())

	for {
		select {
		case <-t.closeTimer:
			t.wg.Done()
			return
		case <-t.ticker.C:
			// This fires every second
			now := getTime()
			if now.Equal(next) || now.After(next) {
				go t.update(next)
				next = timeperiod.From(now).Next().Time()
			}
		}
	}

}

func (t *KeytabCache) firstRun(now time.Time) {

	zap.L().Debug("Running Keytab initial creation")

	t.mutex.RLock()
	defer t.mutex.RUnlock()
	for _, wrapper := range t.internal {
		go wrapper.update(now)
	}

	zap.L().Debug("Completed Keytab initial creation")
}

func (t *KeytabCache) update(now time.Time) {

	zap.L().Debug("Running Keytab update")

	t.mutex.RLock()
	defer t.mutex.RUnlock()
	for _, wrapper := range t.internal {
		go wrapper.update(now)
	}

	zap.L().Debug("Completed Keytab update")
}

func (t *keytabWrapper) update(now time.Time) {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if now.Equal(t.nextUpdate) || now.After(t.nextUpdate) {

		zap.L().Debug(fmt.Sprintf("Keytab %s ready for new keytab", t.principal))

		nowPeriod := t.timePeriod.From(now)
		now = nowPeriod.Time()

		otp, err := totp.GenerateCodeCustom(t.seed, now, totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA512,
		})

		if err != nil {
			zap.L().Error(fmt.Sprintf("Unable to get create keytab %s ; err->%s", t.principal, err.Error()))
			t.err = err
			t.keytab = nil
			return
		}

		hash := sha256.Sum256([]byte(otp + t.seed))

		b := make([]byte, 28)
		for i := range b {
			b[i] = t.getChar(hash[i])
		}

		password := string(b)

		base64File, err := t.newKeytab(password)

		if err != nil {
			zap.L().Error(fmt.Sprintf("Unable to get create keytab %s ; err->%s", t.principal, err.Error()))
			t.err = err
			t.keytab = nil
			return
		}

		t.nextUpdate = nowPeriod.Next().Time()
		t.err = nil
		t.keytab = &libtokenmachine.Keytab{
			Principal:  "HTTP/" + t.principal,
			Base64File: base64File,
			Exp:        nowPeriod.Time().Unix() + int64(t.timePeriod.Duration.Seconds()),
		}

		zap.L().Debug(fmt.Sprintf("Keytab %s generated with exp=%d", t.principal, t.keytab.Exp))
		// zap.L().Debug(fmt.Sprintf("Keytab %s generated with exp=%d and hashed password %s", t.principal, t.keytab.Exp, fmt.Sprintf("%x", sha256.Sum256([]byte(password)))[:12]))

		return
	}

	// zap.L().Debug(fmt.Sprintf("Keytab %s NOT ready for new keytab", t.principal))

}

func (t *keytabWrapper) getChar(b byte) byte {
	bint := int(b)
	charsetlen := len(keytabPasswordCharset)
	if int(b) < charsetlen {
		return keytabPasswordCharset[bint]
	}
	_, r := bint/charsetlen, bint%charsetlen
	return keytabPasswordCharset[r]
}

// GetKeytab Returns Keytab if keytab exist.
func (t *KeytabCache) GetKeytab(name string) (*libtokenmachine.Keytab, error) {

	if name == "" {
		zap.L().Debug("Keytab name is empty")
		return nil, libtokenmachine.ErrNotFound
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if wrapper, exist := t.internal[name]; exist {

		wrapper.mutex.RLock()
		defer wrapper.mutex.RUnlock()

		// Export function; returning copy
		if wrapper.keytab == nil {
			if wrapper.err == nil {
				zap.L().Debug(fmt.Sprintf("Keytab %s has not been processed yet", name))
				return nil, libtokenmachine.ErrNotFound
			}
			zap.L().Debug(fmt.Sprintf("Keytab %s not generated due to error; err->%s", name, wrapper.err.Error()))
			return nil, libtokenmachine.ErrServerFail
		}

		return wrapper.keytab, nil
	}

	zap.L().Debug(fmt.Sprintf("Keytab %s does not exist", name))
	return nil, libtokenmachine.ErrNotFound
}

func (t *keytabWrapper) newKeytab(password string) (string, error) {
	if runtime.GOOS == "windows" {
		return t.windowsNewKeytab(password)
	}
	return t.unixNewKeytab(password)
}

// Windows Kerberos Implementation (Active Directory) allows for the creation
// of principals that are mapped to a user account. Only one principal may be
// mapped to a user account at a time. Once a keytab is created it will remain
// valid until the principal is removed  or the password is changed or a new
// keytab is created. The windows utility ktpass is used to create the keytabs.
// The ktpass command is executed directly on the host. Therefore this should
// be ran on a Windows system that is a member of the target domain. It must
// also be ran with privileges to allow the creation of keytabs. Generally this
// is a Domain Admin. If running as a service it is necessary that it be
// configured to run as a domain admin or user with the privileges necessary
// to create keytabs.
//
// Information about the ktpass utility is as follows
// Exe: C:\Windows\System32\ktpass
// Documentation: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753771(v=ws.11)
// [/out <FileName>]
// [/princ <PrincipalName>]
// [/mapuser <UserAccount>]
// [/mapop {add|set}] [{-|+}desonly] [/in <FileName>]
// [/pass {Password|*|{-|+}rndpass}]
// [/minpass]
// [/maxpass]
// [/crypto {DES-CBC-CRC|DES-CBC-MD5|RC4-HMAC-NT|AES256-SHA1|AES128-SHA1|All}]
// [/itercount]
// [/ptype {KRB5_NT_PRINCIPAL|KRB5_NT_SRV_INST|KRB5_NT_SRV_HST}]
// [/kvno <KeyVersionNum>]
// [/answer {-|+}]
// [/target]
// [/rawsalt] [{-|+}dumpsalt] [{-|+}setupn] [{-|+}setpass <Password>]  [/?|/h|/help]
//
// Use +DumpSalt to dump MIT Salt to output
//
// Notes about ktpass failure functionality
// Testing on Windows Server 2019 reveals that if the user lacks the
// privileges to create keytabs the ktpass utility does not create the
// keytab but also still exits with 0 and nothing is sent to the stdout
// This was with a service account and stderr was not checked. For this
// reason we will return an auth err if the file does not exist. This
// should be refined in the future.
//
// ktpass -mapUser bob@EXAMPLE.COM -pass ** -mapOp set -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -princ HTTP/bob@EXAMPLE.COM -out keytab
//
func (t *keytabWrapper) windowsNewKeytab(password string) (string, error) {

	dir, err := ioutil.TempDir("", "kt")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	filename := dir + `\file.keytab`

	exe := "C:\\Windows\\System32\\ktpass"
	args := []string{}

	args = append(args, "-mapUser")
	args = append(args, t.principal)
	args = append(args, "-pass")
	args = append(args, password)
	args = append(args, "-mapOp")
	args = append(args, "set")
	args = append(args, "-crypto")
	args = append(args, "AES256-SHA1")
	args = append(args, "-ptype")
	args = append(args, "KRB5_NT_PRINCIPAL")
	args = append(args, "-princ")
	args = append(args, "HTTP/"+t.principal)
	args = append(args, "-kvno")
	args = append(args, "1")
	args = append(args, "-out")
	args = append(args, filename)

	logarg := exe
	for _, arg := range args {
		logarg = logarg + " " + arg
	}

	//zap.L().Debug(fmt.Sprintf("command->%s", logarg))

	cmd := exec.Command(exe, args...)
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err = cmd.Run()
	if err != nil {
		zap.L().Error(fmt.Sprintf("exec.Command(%s, %s)", exe, args))
		return "", err
	}

	zap.L().Debug(fmt.Sprintf("command->%s, output->%s", logarg, string(cmdOutput.Bytes())))

	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(f)
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(content), nil
}

func (t *keytabWrapper) unixNewKeytab(password string) (string, error) {
	return "this is not a valid keytab, it is fake", nil
}

// Shutdown shutdown
func (t *KeytabCache) Shutdown() {
	zap.L().Info(fmt.Sprintf("Stopping"))
	close(t.closeTimer)
	t.wg.Wait()
}
