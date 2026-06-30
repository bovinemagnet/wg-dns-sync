// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "fmt"

const (
	ExitCodeSuccess          = 0
	ExitCodeGeneral          = 1
	ExitCodeInvalidArguments = 2
	ExitCodeInvalidConfig    = 3
	ExitCodeDNSFailure       = 4
	ExitCodeWireGuardFailure = 5
	ExitCodeWriteFailure     = 6
)

type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

func wrapExit(code int, err error) error {
	if err == nil {
		return nil
	}
	return ExitError{Code: code, Err: err}
}
