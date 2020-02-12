# pass

`pass` is a very simple password manager that uses `libsodium` for cryptography.

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
pass set email/yahoo.com
```

Retrieve a password.
```sh
pass get gmail.com
pass get email/yahoo.com
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
