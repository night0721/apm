# apm
A simple implementation of [pass](https://www.passwordstore.org/)(1) in C. It uses a unique key to encrypt every password, it provides functionality to edit, add, generate, show, list, remove passwords. It uses blake2b to create hash of master password and uses AES256-CBC to encrypt the password.

Before using apm, you must export 2 environment variables in order to make it work
```sh
export APM_DIR=~/secret/apm
export APM_KEY=~/secret/apm_key
```

`APM_DIR` is the directory where passwords are stored and `APM_KEY` is the path to the master key file.

[AES256 Implementation](https://github.com/halloweeks/AES-256-CBC) [Blake2b Implementation](https://github.com/jamesvan2019/blake2b_c)

# Usage
```
Usage: apm [-vhL] [[-e | -R | -I | -Q] <password>] [-M <file>] [-G <password> <length>]
```

# Dependencies
None

# Building
You will need to run these with elevated privilages.
```
$ make
# make install
```

# Contributions
Contributions are welcomed, feel free to open a pull request.

# License
This project is licensed under the GNU Public License v3.0. See [LICENSE](https://github.com/night0721/apm/blob/master/LICENSE) for more information.
