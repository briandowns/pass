# pass

[![Build Status](https://travis-ci.org/briandowns/pass.svg?branch=master)](https://travis-ci.org/briandowns/pass)

`pass` is a very simple password manager inspired by `pass` but without the use of GnuPG. It uses `libsodium` for cryptography.

## Features

* Generate AES Keys
* Save passwords
* Retrieve passwords
* Backup passwords and keys

## Examples

## Requirements

libsodium is used for cryptography and will need to be installed prior to compiling `pass`.

* MacOS

`brew install libsodium`

* Apt

`sudo apt-get install -y libsodium-dev`

* FreeBSD

`pkg install libsodium`

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
