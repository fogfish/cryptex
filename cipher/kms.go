//
// Copyright (C) 2020 Dmitry Kolesnikov
//
// This file may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
// https://github.com/fogfish/cryptex
//

package cipher

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// KMS is the context of AWS KMS cipher
type KMS struct {
	api kmsiface.KMSAPI
	key string
}

// NewKMS returns AWS KMS context
func NewKMS(api ...kmsiface.KMSAPI) *KMS {
	if len(api) > 0 {
		return &KMS{api: api[0], key: ""}
	}

	return &KMS{
		api: kms.New(session.Must(session.NewSession())),
		key: "",
	}
}

// UseKey defines encryption key
func (c *KMS) UseKey(key string) {
	c.key = key
}

// Decrypt uses AWS KMS API to decrypt cryptotext.
func (c *KMS) Decrypt(cryptotext string) (plaintext []byte, err error) {
	return c.Decrypt64(b64, cryptotext)
}

// Decrypt64 uses AWS KMS API to decrypt cryptotext.
func (c *KMS) Decrypt64(codec *base64.Encoding, cryptotext string) (plaintext []byte, err error) {
	bytes, err := codec.DecodeString(cryptotext)
	if err != nil {
		return
	}

	input := &kms.DecryptInput{
		CiphertextBlob: []byte(bytes),
	}

	result, err := c.api.Decrypt(input)
	if err != nil {
		return
	}

	return result.Plaintext, nil
}

// Encrypt uses AWS KMS API to encrypt plaintext.
func (c *KMS) Encrypt(plaintext []byte) (cryptotext string, err error) {
	return c.Encrypt64(b64, plaintext)
}

// Encrypt64 uses AWS KMS API to encrypt plaintext.
func (c *KMS) Encrypt64(codec *base64.Encoding, plaintext []byte) (cryptotext string, err error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(c.key),
		Plaintext: plaintext,
	}

	result, err := c.api.Encrypt(input)
	if err != nil {
		return
	}

	return codec.EncodeToString(result.CiphertextBlob), nil
}
