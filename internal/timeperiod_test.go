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
	"fmt"
	"testing"
	"time"
)

func Test1(t *testing.T) {

	epochPeriod := NewPeriod(time.Duration(2) * time.Minute)
	now := time.Date(2020, 3, 12, 14, 10, 0, 0, time.UTC)
	nowPeriod := epochPeriod.From(now)
	nextPeriod := nowPeriod.Next()
	prePeriod := nowPeriod.Prev()

	pnow := fmt.Sprintf("%s", time.Unix(nowPeriod.Epoch, 0))
	pnext := fmt.Sprintf("%s", time.Unix(nextPeriod.Epoch, 0))
	pprev := fmt.Sprintf("%s", time.Unix(prePeriod.Epoch, 0))

	if pnow != "2020-03-12 09:10:00 -0500 CDT" {
		t.Fatalf("Period now fail")
	}

	if pnext != "2020-03-12 09:12:00 -0500 CDT" {
		t.Fatalf("Period next fail")
	}

	if pprev != "2020-03-12 09:08:00 -0500 CDT" {
		t.Fatalf("Period prev fail")
	}

}

func Test2(t *testing.T) {

	epochPeriod := NewPeriod(time.Duration(12) * time.Minute)
	now := time.Date(2022, 1, 12, 18, 10, 0, 0, time.UTC)
	nowPeriod := epochPeriod.From(now)
	nextPeriod := nowPeriod.Next()
	prePeriod := nowPeriod.Prev()

	pnow := fmt.Sprintf("%s", time.Unix(nowPeriod.Epoch, 0))
	pnext := fmt.Sprintf("%s", time.Unix(nextPeriod.Epoch, 0))
	pprev := fmt.Sprintf("%s", time.Unix(prePeriod.Epoch, 0))

	if pnow != "2022-01-12 12:00:00 -0600 CST" {
		t.Fatalf("Period now fail")
	}

	if pnext != "2022-01-12 12:12:00 -0600 CST" {
		t.Fatalf("Period next fail")
	}

	if pprev != "2022-01-12 11:48:00 -0600 CST" {
		t.Fatalf("Period prev fail")
	}

}

func Test3(t *testing.T) {

	epochPeriod := NewPeriod(time.Duration(2) * time.Hour)
	now := time.Date(2022, 1, 19, 18, 13, 0, 0, time.UTC)
	nowPeriod := epochPeriod.From(now)
	nextPeriod := nowPeriod.Next()
	prePeriod := nowPeriod.Prev()

	pnow := fmt.Sprintf("%s", time.Unix(nowPeriod.Epoch, 0))
	pnext := fmt.Sprintf("%s", time.Unix(nextPeriod.Epoch, 0))
	pprev := fmt.Sprintf("%s", time.Unix(prePeriod.Epoch, 0))

	if pnow != "2022-01-19 12:00:00 -0600 CST" {
		t.Fatalf("Period now fail")
	}

	if pnext != "2022-01-19 14:00:00 -0600 CST" {
		t.Fatalf("Period next fail")
	}

	if pprev != "2022-01-19 10:00:00 -0600 CST" {
		t.Fatalf("Period prev fail")
	}

}

func Test4(t *testing.T) {

	epochPeriod := NewPeriod(time.Duration(1) * time.Hour).From(time.Date(2022, 1, 19, 18, 0, 0, 0, time.UTC))

	upper := time.Date(2022, 1, 19, 18, 27, 0, 0, time.UTC)
	lower := time.Date(2022, 1, 19, 18, 44, 0, 0, time.UTC)

	if epochPeriod.HalfLife(upper) {
		t.Fatalf("not expected")
	}

	if !epochPeriod.HalfLife(lower) {
		t.Fatalf("not expected")
	}

}
