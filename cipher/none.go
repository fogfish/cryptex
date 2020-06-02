//
// Copyright (C) 2020 Dmitry Kolesnikov
//
// This file may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
// https://github.com/fogfish/cryptex
//

package cipher

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// NewNone creates identity (none) codecs
func NewNone() *KMS {
	return NewKMS(&none{})
}

//
//
type none struct {
	kmsiface.KMSAPI
}

func (none) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return &kms.DecryptOutput{
		Plaintext: input.CiphertextBlob,
	}, nil
}

func (none) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	return &kms.EncryptOutput{
		CiphertextBlob: input.Plaintext,
	}, nil
}
