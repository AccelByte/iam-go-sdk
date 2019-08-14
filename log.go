// Copyright (c) 2019 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package iam

import "fmt"

func log(s ...interface{}) {
	if !debug {
		return
	}

	fmt.Print("[IAM-Go-SDK] ")
	fmt.Println(s...)
}

func logErr(err error, s ...interface{}) {
	if !debug {
		return
	}

	if err == nil {
		return
	}

	fmt.Print("[IAM-Go-SDK] ")
	fmt.Println(s...)
	fmt.Printf("%+v\n", err)
}

// nolint: unparam
func logAndReturnErr(err error, s ...interface{}) error {
	logErr(err, s...)
	return err
}
