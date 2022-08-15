# pass

`pass` is a simple password manager.

## Examples

Initialize `pass`. This is necessary to create a new key and setup the base directory structure.

```sh
pass init
```

```sh
PASS_DIR=/path/to/somewhere pass init
```

Store a password:
```sh
pass set email/gmail
pass set email/yahoo
```

Retrieve a password:
```sh
pass get email/gmail
pass get email/yahoo
```

List passwords:
```sh
pass ls
- video/
    - netflix
    - espn
- social/
    - twitter
- audio/
    - spotify
- banks/
    - bofa
- email/
    - suse
    - gmail
```

Generate a new password with a length of 12:
```sh
pass gen 12
```

Check the complexity of a password:
```sh
$ pass check 'asd7sjshs5('
report:
  greater than 8: y
  has lower:      y
  has upper:      n
  has special:    y
  in dictionary:  n
```

## Requirements

libsodium is used for cryptography and will need to be installed prior to compiling `pass`.

* MacOS

`brew install libsodium`

* FreeBSD

`pkg install libsodium`

* Apt

`apt-get install -y libsodium-dev`

* Apk

`apk add libsodium-static libsodium-dev`

## Build & Install

```sh
make install
```

## Contact

[@bdowns328](http://twitter.com/bdowns328)
