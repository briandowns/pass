# pass

`pass` is a very simple password manager inspired by `pass` but without the use of GnuPG. It uses `libsodium` for cryptography.

## Features

* Generate AES Keys
* Save passwords
* Retrieve passwords
* Backup passwords and keys

## Examples

Initialize pass.

```sh
pass init
```

```sh
PASS_DIR=/path/to/somewhere pass init
```

Set a password.

```sh
pass set gmail.com
```

Retrieve a password.
```sh
pass get gmail.com
```

## Requirements

libsodium is used for cryptography and will need to be installed prior to compiling `pass`.

* MacOS

`brew install libsodium`

* FreeBSD

`pkg install libsodium`

* Apt

`sudo apt-get install -y libsodium-dev`

## Build

```sh
make
```

## Install 

```sh
make install
```

## Test

```sh
make test
```

## Contact

[@bdowns328](http://twitter.com/bdowns328)
