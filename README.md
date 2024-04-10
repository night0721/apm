# argon

A minimalistic command line password manager and a rewrite of [pass](https://www.passwordstore.org/) in C.  It uses a unique key to encrypt every password, it provides functionality to edit, add, generate, show, list, remove passwords. It uses argon2 to create hash of master password and uses XSalsa20 to encrypt the password.

> The name "argon" is chosen as it uses argon2 algorithm and sodium(library) is stored with argon.

Before using argon, you must export 2 environment variables in order to make it work
```sh
export ARGON_DIR=~/secret/argon
export ARGON_KEY=~/secret/argon_key
```

`ARGON_DIR` is the directory where passwords are stored and `ARGON_KEY` is the path to the master key file.

# Dependencies
- libsodium 
- gcc

# Building
```sh
$ make
# make install
```

# Usage
```
Usage: argon [-vhL] [[-e | -R | -I | -Q] <password>] [-M <file>] [-G <password> <length>]
```

# Contributions
Contributions are welcomed, feel free to open a pull request.

# License
This project is licensed under the GNU Public License v3.0. See [LICENSE](https://github.com/night0721/argon/blob/master/LICENSE) for more information.
