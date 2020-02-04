//
// Code generated by `golem` package
// Source: github.com/fogfish/cryptex/cryptex.go
// Time: 2020-02-04 17:05:39.582562 +0000 UTC
//
//
// Copyright (C) 2020 Dmitry Kolesnikov
//
// This file may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
// https://github.com/fogfish/golem
//

package identity

import (
	"encoding/json"

	"github.com/fogfish/cryptex/cipher"
	
)

// AnyT is generic definition of sensitive structures
type Cryptex Identity

// UnmarshalJSON implements automatic decryption of data
func (value *Cryptex) UnmarshalJSON(b []byte) (err error) {
	type Referable Cryptex

	var cryptotext string
	if err = json.Unmarshal(b, &cryptotext); err != nil {
		return
	}

	text, err := cipher.Default.Decrypt(cryptotext)
	if err != nil {
		return
	}

	var gen Referable
	if err = json.Unmarshal(text, &gen); err != nil {
		return
	}

	*value = Cryptex(gen)
	return
}

// MarshalJSON implements automatic encryption of sensitive strings during data marshalling.
func (value Cryptex) MarshalJSON() (bytes []byte, err error) {
	type Referable Cryptex

	binary, err := json.Marshal(Referable(value))
	if err != nil {
		return
	}

	text, err := cipher.Default.Encrypt(binary)
	if err != nil {
		return
	}

	return json.Marshal(text)
}

// PlainText returns plain text value
func (value Cryptex) PlainText() Identity {
	return Identity(value)
}
