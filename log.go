// Copyright 2019 AccelByte Inc
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

import "fmt"

func log(s ...interface{}) {
	if !debug.Load() {
		return
	}

	fmt.Print("[IAM-Go-SDK] ")
	fmt.Println(s...)
}

func logErrWithStackTrace(err error, s ...interface{}) {
	doLogErr(err, true, s)
}

func logAndReturnErr(err error, s ...interface{}) error {
	doLogErr(err, false, s)
	return err
}

func logWithStackTraceAndReturnErr(err error, s ...interface{}) error {
	doLogErr(err, true, s)
	return err
}

func doLogErr(err error, printStackTrace bool, s ...interface{}) {
	if !debug.Load() {
		return
	}

	if err == nil {
		return
	}

	fmt.Print("[IAM-Go-SDK] ")
	fmt.Println(s...)
	if printStackTrace {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("%+v\n", err.Error())
	}
}
