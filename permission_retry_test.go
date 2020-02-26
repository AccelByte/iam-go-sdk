package iam

import (
	"testing"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func TestRetry(t *testing.T) {
	const successOn = 3

	var i = 0

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
