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

package util

import "time"

// Example
// epochPeriod := NewPeriod(time.Duration(2) * time.Hour)
// now := time.Date(2022, 1, 19, 18, 13, 0, 0, time.UTC)
// nowPeriod := epochPeriod.From(now)
// nextPeriod := nowPeriod.Next()
// prePeriod := nowPeriod.Prev()

// TimePeriod Period of time defined by duration and epoch where epoch is the
// start of the TimePeriod
type TimePeriod struct {
	Duration time.Duration
	Epoch    int64
}

// NewPeriod Returns first Period from epoch with provided duration
func NewPeriod(duration time.Duration) *TimePeriod {
	return &TimePeriod{
		Duration: duration,
		Epoch:    0,
	}
}

// Next Returns first Period after current
func (t *TimePeriod) Next() *TimePeriod {
	return &TimePeriod{
		Duration: t.Duration,
		Epoch:    t.Epoch + int64(t.Duration.Seconds()),
	}
}

// Prev Returns First Period before current
func (t *TimePeriod) Prev() *TimePeriod {
	// Once we hit 0 or Jan 1 1970 we can not go back anymore so we just keep
	// returning Jan 1 1970
	epoch := t.Epoch - int64(t.Duration.Seconds())
	if epoch < 0 {
		epoch = 0
	}
	return &TimePeriod{
		Duration: t.Duration,
		Epoch:    epoch,
	}
}

// Time Returns period time where time is the top of the period
func (t *TimePeriod) Time() time.Time {
	return time.Unix(t.Epoch, 0)
}

// From Returns Period period that contains provided time
func (t *TimePeriod) From(input time.Time) *TimePeriod {
	// Determine number of seconds time is from top of current period and subtract
	// them hence top of period
	epoch := input.Unix()
	s := int64(t.Duration.Seconds())
	_, remainderSeconds := epoch/s, epoch%s
	epoch = epoch - remainderSeconds

	return &TimePeriod{
		Duration: t.Duration,
		Epoch:    epoch,
	}
}

// HalfLife true if TimePeriod has reached half life
func (t *TimePeriod) HalfLife(input time.Time) bool {
	if input.Unix()-t.Epoch > int64(t.Duration.Seconds())/2 {
		return true
	}
	return false
}
