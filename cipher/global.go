//
// Copyright (C) 2020 Dmitry Kolesnikov
//
// This file may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
// https://github.com/fogfish/cryptex
//

// Package cipher implements crypto algorithms for crypto generic.
package cipher

import "encoding/base64"

var (
	// Default is global variable with reference to default cipher.
	Default = NewKMS()

	// base64url encoding
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
)
