<p align="center">
  <h3 align="center">Cryptex</h3>
  <p align="center"><strong>Passing Sensitive Data with JSON</strong></p>

  <p align="center">
    <!-- Documentation -->
    <a href="http://godoc.org/github.com/fogfish/cryptex">
      <img src="https://godoc.org/github.com/fogfish/cryptex?status.svg" />
    </a>
    <!-- Build Status  -->
    <a href="http://travis-ci.org/fogfish/cryptex">
      <img src="https://secure.travis-ci.org/fogfish/cryptex.svg?branch=master" />
    </a>
    <!-- GitHub -->
    <a href="http://github.com/fogfish/cryptex">
      <img src="https://img.shields.io/github/last-commit/fogfish/cryptex.svg" />
    </a>
    <!-- Coverage -->
    <a href="https://coveralls.io/github/fogfish/cryptex?branch=master">
      <img src="https://coveralls.io/repos/github/fogfish/cryptex/badge.svg?branch=master" />
    </a>
    <!-- Go Card -->
    <a href="https://goreportcard.com/report/github.com/fogfish/cryptex">
      <img src="https://goreportcard.com/badge/github.com/fogfish/cryptex" />
    </a>
  </p>
</p>

--- 

> The word cryptex is a neologism coined by the author Dan Brown for his 2003 novel The Da Vinci Code, denoting a portable vault used to hide secret messages.

Encryption **in transit** and **at rest** are best practices to deal with sensitive data. Software engineers MUST ensure that the data is always transmitted using strong encryption standards and also protected with strong encryption at storages. Cloud Services offers rich variate of products to deal with it - [AWS Key Management](https://aws.amazon.com/kms/) is great example. It implements a centralized control over the cryptographic keys and integrates with other AWS services to encrypt data.

The encryption works transparently inside cloud services. It becomes a responsibility of engineers to handle sensitive data outside of the cloud. The usage of traditional operating system services opens few [issues](https://baffle.io/encrypting-data-is-complex):

* disk level encryption protects against physical theft. Operating system services clear text to any one.

* transparent data encryption protects against direct file system access. The database engine provides clear text to its applications.

AWS KMS provides [SDK](https://docs.aws.amazon.com/sdk-for-go/api/service/kms/) for developers to integrate encryption to they application. You can benefit from strong encryption with ability of fine-grained access control to sensitive data for application that runs outside of AWS data centers. AWS KMS helps you with implementation of Application Level Encryption and Record Level Encryption - encryption of fields in a structured data using different keys for different instances. The IAM roles delegates rights to decrypt sensitive data. 

[The design of KMS](https://d0.awsstatic.com/whitepapers/KMS-Cryptographic-Details.pdf) ensures that no one, including AWS employees, can get access to your encryption keys. This key management solution is compliant with FIPS 140-2 and audited by independent groups.


## Encryption of structured data

Here we are continue discussion about the developer friendly solution to apply Application/Record Level Encryption with help of KMS for sensitive structured data (e.g. JSON). My design aims to address few requirements:

* transparent for developers - encryption/decryption is built with semi-auto codec. It makes a "magic" of switching representation between crypto/plain texts. Developer just declares the intent to protect sensitive data. 

* compile time type-safeness - the sensitive data is modelled with algebraic data types. The type tagging (annotation) is used to declare the the intent to protect sensitive data. Golang compiler discover and prevents type errors or other glitches at the time it assembles binaries.

* generic - encryption/decryption are generic algorithms applicable to any algebraic data types (not only to strings). The library provides ability to apply algorithms for any product type in developer's application context.

* [data in use](https://en.wikipedia.org/wiki/Data_in_use) **is not supported**. Developers have to combine this library with [MemGuard](https://github.com/awnumar/memguard).   


## Golang Encryption Codec

Golang has excellent [built-in abstraction](https://blog.golang.org/json-and-go) to encode/decode structured data into JSON data interchange format. We embed crypto codec into `json.Marshal` and `json.Unmarshal` routines so that protection of sensitive data is semi-automatic during the process of data serialization.

```go
MyADT{Secret: "plaintext"} ⟷ {"secret":"cGxhaW50ZXh0"}
```

Semi-automatic encryption can be achieved either using [struct tags](https://medium.com/golangspec/tags-in-golang-3e5db0b8ef3e) or custom types. Struct tags is a feature to annotate algebraic data types but it requires usage of reflection, which do not provide compile type safeness. This library implements final type to encrypt/decrypt strings `cryptex.String` and generic type `cryptex.AnyT`, which allows to handle any application specific algebraic data types.

### AWS KMS SDK

Crypto binary data is produced either by [AWS KMS SDK](https://docs.aws.amazon.com/sdk-for-go/api/service/kms/) or AWS command line utility. The following code sketches usage of KMS to protect sensitive data. Note: error handling is skipped just to illustrate usage of api.

```golang
func Decrypt(cryptotext string) plaintext []byte {
  bytes, err := base64.StdEncoding.DecodeString(cryptotext)
	input := &kms.DecryptInput{ CiphertextBlob: []byte(bytes) }
	result, err := kms.api.Decrypt(input)
	return result.Plaintext
}

func Encrypt(plaintext []byte) cryptotext string {
	input := &kms.EncryptInput{
		KeyId:     aws.String(kms.key),
		Plaintext: plaintext,
	}
	result, err := kms.api.Encrypt(input)
	return base64.StdEncoding.EncodeToString(result.CiphertextBlob)
}
```

### Strings encryption

Use `cryptex.String` to deal with sensitive textual content. Its implementation assumes that binary crypto text is encoded with base64url, which makes is usable with any text-based protocols, file names and URLs.

The usage of `cryptex.String` data type in your application is straight forward:

```go
import (
	"github.com/fogfish/cryptex"
	"github.com/fogfish/cryptex/cipher"
)

// You have to define either KMS key id or its alias if your application needs to
// encrypt data. You can skip this state if you application only decrypts data.
cipher.Default.UseKey("alias/mykms-key")

// Do not use built-in `string` type for sensitive data in data structure, which
// leaves boundaries of your application (e.g. sent to client, stored to disk, etc).
// Use `cryptex.String` instead.
type User struct {
  Password cryptex.String `json:"password"`
}

// The type of `cryptex.String` is used as usual to keep your plain text data in memory.
// A sensitive value is not assignable to variable of type `string`. You have to either 
// use helper method `PlainText` e.g. `user.Password.PlainText()` or cast it to string.
// A simple protection against accidental leakage.
user := User{"sensitive data"}

// The data is automatically encrypted when you marshal it to the-wire format
// The output JSON looks like {"password":"cGShaW53ZXh0..."}
bytes, err := json.Marshal(&user)

// The data is automatically decrypted when you unmarshall it.
err := json.Unmarshal(bytes, &user)
```

### Algebraic Data Types encryption

You might experience encryption overhead if multiple fields with sensitive textual data are involved. It becomes more efficient to use product data type as a container of sensitive data. Use [golem generic](https://github.com/fogfish/golem/tree/master/generic) to parametrize `cryptex.AnyT` with your data type. `cryptex.AnyT` converts Algebraic Data Types to JSON then encrypts and applies base64 transformation. Use `go generate` to parametrize generic algorithm with you data type. Here is a minimal example 

```go
// Just create a package for your ADT. Add the following line to comments.
// It instructs code generator to parametrize generic algorithm with you data type.
//go:generate golem -T Identity -generic github.com/fogfish/cryptex/cryptex.go
package identity

// Declare a type as standard golang struct.
type Identity struct {
  Email    string `json:"email"`
  Password string `json:"password"`
  PinCode  int    `json:"pincode"`
}
```

As the result, you'll get new data type `identity.Cryptex`. It knows how to encrypt/decrypt your ADT. Its usage is straight forward:

```go
import (
  ".../identity"
)

// Do not use plain text type. Use `identity.Cryptex` it ensures protection of
// sensitive data when it leaves boundaries of your application.
type User struct {
  Identity identity.Cryptex `json:"identity"`
}

// `identity.Cryptex` is an alias to `identity.Identity` type. Instantiate it with
// same interface as original one.
user := User{
  Identity: identity.Cryptex{
    Email:    "any@example.com",
    Password: "sensitive data",
    PinCode:  1234,
  },
}

// The data is automatically encrypted when you marshal it to the-wire format
// The output JSON looks like {"identity":"cGShaW53ZXh0..."}. The data is
// automatically decrypted and re-packed to struct when you unmarshall it.
bytes, err := json.Marshal(&user)
err := json.Unmarshal(bytes, &user)
```

### Environment Variables

Usage of Environment Variables is a [common approach](https://12factor.net/config) to store application configuration. Encryption is required to deal with credentials or other sensitive
data. Use AWS command-line and this library to protect your config:

```bash
aws kms encrypt \
  --key-id alias/mykms-key \
  --plaintext "PlainText" \
  --query CiphertextBlob \
  --output text

export MY_CONFIG=...
```

Cryptex library implements Golang standard semantic (`os` package) to deal with environment 
variables. It transparently encrypt/decrypt them with KMS key.

```go
cryptex.Getenv("MY_CONFIG")
cryptex.LookupEnv("MY_CONFIG")
```


## Afterwords

Software engineers are responsible to retain confidentiality of sensitive data in they applications. The usage of cloud service offers variate of products to deal with data encryptions, which works transparently inside cloud services. It becomes a responsibility of engineers to handle sensitive data outside of the cloud.

You can benefit from this library. It implements semi-auto cipher codec of textual content and custom Algebraic Data Types. Encryption/Decryption process is transparent for developers. It is embedded into `json.Marshal` and `json.Unmarshal` routines so that protection of sensitive data happens during the process of data serialization.

See the complete example [here](example/main.go).

## License

[![See LICENSE](https://img.shields.io/github/license/fogfish/cryptex.svg?style=for-the-badge)](LICENSE)