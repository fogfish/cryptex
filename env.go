//
// Copyright (C) 2020 Dmitry Kolesnikov
//
// This file may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
// https://github.com/fogfish/cryptex
//

package cryptex

import (
	"encoding/base64"
	"os"

	"github.com/fogfish/cryptex/cipher"
)

/*

Setenv sets the value of environment variable
*/
func Setenv(key, value string) error {
	text, err := cipher.Default.Encrypt64(base64.StdEncoding, []byte(value))
	if err != nil {
		return err
	}

	return os.Setenv(key, text)
}

/*

Getenv retrieves the value of the environment variable named by
the key. Returns empty string if variable do not exists or application do
not have permission to use encryption key.
*/
func Getenv(key string) string {
	value, exists := LookupEnv(key)
	if !exists {
		return ""
	}

	return value
}

/*

LookupEnv retrieves the value of the environment variable named by
the key. Returns false if variable do not exists or application do
not have permission to use encryption key.
*/
func LookupEnv(key string) (string, bool) {
	cryptotext, exists := os.LookupEnv(key)
	if !exists {
		return "", false
	}

	text, err := cipher.Default.Decrypt64(base64.StdEncoding, cryptotext)
	if err != nil {
		return "", false
	}

	return string(text), true
}
