PII
============
[![Coverage Status](https://coveralls.io/repos/github/ln80/pii/badge.svg?branch=setup_ci)](https://coveralls.io/github/ln80/pii)
[![GoDoc](https://godoc.org/github.com/ln80/pii?status.svg)](https://godoc.org/github.com/ln80/pii)
![ci status](https://github.com/ln80/pii/actions/workflows/pipeline.yml/badge.svg)

#### A pluggable Go library to protect [Personal Identifiable Information](https://en.wikipedia.org/wiki/Personal_data) at the struct field level.

#### **TLDR; PII** simplifies encryption and [cryptographic erasure](https://en.wikipedia.org/wiki/Crypto-shredding).


## Motivation

**PII** may considerably help if you are:

- Following [Privacy By Design](https://en.wikipedia.org/wiki/Privacy_by_design#Foundational_principles_in_detail) principles.
- Looking for a solution to comply with privacy standards (ex: GDPR) while using [Event Sourcing](https://martinfowler.com/eaaDev/EventSourcing.html) or an immutable store.

## Project Status

The library is **experimental**; breaking changes may occur based on developer experience.

**`v1.0.0`** aims to be the first stable version.


## Getting Started

### Installation:

```shell
    $ go get github.com/ln80/pii
```
```go
    import "github.com/ln80/pii"
```

### At your struct level:

```go
type Person struct {
    UserID   string `pii:"subjectID,prefix=account-"`
    Fullname string `pii:"data,replace=forgotten user"`
    Gender   string `pii:"data"`
    Country  string
}
```

- Tag the field representing the `Subject ID` (ex: UserID)
- Tag `Personal data` fields to encrypt (only string fields are supported at the moment)

`prefix` option is added to the field value to define the subject ID.

`replace` option is used to replace the crypto-erased field value. Otherwise, the field value will be empty.


### At the root level (ex: main func):

Initiate the `Factory` service:
```go
func main() {
    ctx := context.Background()

    // builder func used by factory service to instantiate a Protector service per namespace
    builder := func(namespace string) pii.Protector {
        // engine handles encryption keys storage and lifecycle
        engine := memory.NewKeyEngine()

        return pii.NewProtector(namespace, enigne, func(pc *pii.ProtectorConfig) {
            pc.CacheEnabled = true
            pc.CacheTTL = 10 * time.Minute
            pc.GracefulMode = true
        })
    }

    // Factory must be injected as dependency in the functional code (ex: HTTP handlers)
    f := pii.NewFactory(builder)

    // In a separated Goroutine, supervise and regularly clear resources
    f.Monitor(ctx)
}
```

### At the functional level (ex: HTTP handler):

- Instantiate `Protector` service by passing the namespace (ex: tenant ID)
- Use the `Protector` to `Encrypt/Decrypt` structs that contain `Personal data`:

```go
func MakeSignupHandler(f pii.Factory, store UserStore) http.HandlerFunc {

        return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        var per Person
        err := json.NewDecoder(r.Body).Decode(&per)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        // Get the protector service for the given namespace
        nspace := r.Header.Get("Tenant-ID")
        prot, clear := f.Instance(nspace)
        
        // Optional, Force clearing cache of encryption materials (related to namespace)
        defer clear()

        // Encrypt Person struct which contains PII.
        if err := prot.Encrypt(ctx, per); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        ...

        if err := store.Save(ctx, per); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        ...
    }
}

```
Note that Factory service maintains a single thread-safe `Protector` service per namespace.

Under the hood, the `Protector` service generates a single encryption key per `Subject ID` and securely saves it in a `Database`.


### Crypto Erasure:

Allows to `Forget` a subject's `Personal data` by first disabling, then deleting the associated encryption materials.

```go
    ...

    if err := prot.Forget(ctx, subjectID); err != nil {
        return err
    }

    ...

    if err := prot.Recover(ctx, subjectID); err != nil {
        if errors.Is(err, pii.ErrCannotRecoverSubject) {
            fmt.Print("Sorry it's late. Good bye forever")
        }

        return err
    }

```
Forgetting a subject means we can't decrypt nor encrypt any of its old or new `Personal data`.

Forgetting the encryption key and not being able to decrypt personal is likely accepted by most `Privacy Standards` as deletion of PII.
Nonetheless, you may need to seek legal advice related to your specific context.

Depending on `Graceful Mode` config, a subject encryption materials can be recovered within a grace period (to define) or not.


## Plugins

`Protector` service uses plugins to manage encryption keys and the encryption algorithm.

You can use your own implementation for each pluggin:

```go
    b := func(namespace string) pii.Protector {
        return pii.NewProtector(namespace, nil, func(pc *pii.ProtectorConfig) {

            pc.Encrypter = MyCustomAlgorithm()

            pc.Engine = MyCustomWrapper(
                MyCustomKeyEngine(),
            )
        })
    }

    f := NewFactory(b)
```


### Encryption algorithm:
By default, **PII** uses `AES 256 GCM` for encryption. 

By implementing `core.Encrypter` interface, you take responsibility, and you use your favorite algorithm (likely to respond to security standards requirements).

### Key Engine:
Responsible for storing encryption keys and managing their life cycle.

**PII** comes with two basic implementations: 

- **Dynamodb**: keys are saved in plain text in an [AWS Dynamodb](https://aws.amazon.com/dynamodb/) table. ([server-side encryption](https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/client-server-side.html) can be applied).

- **In-memory**: used for test purposes.


and two wrappers:

**KMS Wrapper**: uses [AWS KMS](https://aws.amazon.com/kms/) service to allow [Envelope Encryption](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html); client-side encryption of subjects' keys using a [KMS Key](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#kms_keys) as a `Master Key`.

**Memory Cache**: saves keys in memory for a limited period to enhance performance and reduce costs.

Use your custom logic by implementing `core.KeyEngine`, `core.KeyEngineWrapper` or `core.KeyEngineCache`. 


## Limitations

// TODO

## Usage and documentation

Please see https://pkg.go.dev/github.com/ln80/pii for detailed usage docs.


## License

Distributed under MIT License.
