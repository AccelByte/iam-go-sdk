// Copyright 2021 AccelByte Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iam

import (
	"testing"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func TestRetry(t *testing.T) {
	t.Parallel()

	const successOn = 3

	i := 0

	// This function is successful on "successOn" calls.
	f := func() error {
		i++
		logrus.Printf("function is called %d. time\n", i)

		if i == successOn {
			logrus.Println("OK")
			return nil
		}

		logrus.Println("error")

		return errors.New("error")
	}

	err := backoff.Retry(f, backoff.NewExponentialBackOff())
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if i != successOn {
		t.Errorf("invalid number of retries: %d", i)
	}
}
