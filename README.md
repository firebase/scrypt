# Firebase Authentication Password Hashing
Firebase Authentication uses an internally modified version of scrypt to hash
account passwords. Even when an account is uploaded with a password using a
different algorithm, Firebase Auth will rehash the password the first time that
account successfully logs in. Accounts downloaded from Firebase Authentication
will only ever contain a password hash if one for this version of scrypt is
available, or contain an empty password hash otherwise.

See README_SCRYPT for more information about the scrypt library.

## Table of Contents

 * [Finding the Password Hash Parameters](#finding-the-password-hash-parameters)
 * [Downloading User Accounts](#downloading-user-accounts)
 * [Building ](#building)
 * [Password Hashing](#password-hashing)
 * [Other languages](#other-languages)

## Finding the Password Hash Parameters
Firebase generates unique password hash parameters for each Firebase project. To
access these parameters, navigate to the 'Users' tab of the 'Authentication'
section in the Firebase Console and select 'Password Hash Parameters' from the
drop down in the upper-right hand corner of the users table.

## Downloading User Accounts
The `auth:export` command is usd to export user accounts to JSON and CSV files.
Please visit https://firebase.google.com/docs/cli/auth to learn more about
exporting your project's users accounts. For password hashing, you will need the
Password Hash and Password Salt fields for the exported accounts.

### Building
To build scrypt, see the BUILDING file.

## Password Hashing
A simple password-based encryption utility is available as a demonstration of
the `scrypt` library. It can be invoked as `scrypt {key} {salt} {rounds}
{memcost} [-P]`. The utility will ask for a plain text password and output a
hash upon success. This hash should be encoded to base64 and compared to the
password hash of the exported user account.

* {key} - The signer key from the project's password hash parameters. This key
  must be decoded from base64 before being passed to the utility.
* {salt} - Concatenation of the password salt from the exported account and the
  salt separator from the project's password hash parameters. Each half must be
  decoded from base64 before concatenation.
* {rounds} - The rounds parameter from the project's password hash parameters.
* {memcost} - The mem_cost parameter from the project's password hash
  parameters.
* [-P] - An optional `-P` may also be supplied to allow for the raw text
  password to be read from STDIN.

Sample Password hash parameters from Firebase Console:

```
hash_config {
  algorithm: SCRYPT,
  base64_signer_key: jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==,
  base64_salt_separator: Bw==,
  rounds: 8,
  mem_cost: 14,
}
```

Exporting a project's accounts:

```
# Export a project's accounts to a local csv file
$ firebase auth:export --project my-awesome-project-42be4 users.csv
# Inspect the exported accounts
$ cat users.csv
kYi4EvWQlQTKSfnJ3dRSP6IH3ed2,user1@test.com,false,lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==,42xEC+ixf3L2lw==,Test
User 1,,,,,,,,,,,,,,,,,,,1508893925000,1508893925000,,
```

Using the utility:

```
# Params from the project's password hash parameters
base64_signer_key="jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
base64_salt_separator="Bw=="
rounds=8
memcost=14

# Params from the exported account
base64_salt="42xEC+ixf3L2lw=="

# The users raw text password
password="user1password"

# Generate the hash
# Expected output:
# lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==
echo `./scrypt "$base64_signer_key" "$base64_salt" "$base64_salt_separator" "$rounds" "$memcost" -P <<< "$password"`
```

## Other Languages
Thank you to members of the Firebase community that have ported this library to other languages!  See the examples below:

* [firebase-scrypt-java](https://github.com/SmartMoveSystems/firebase-scrypt-java) by [SmartMoveSystems](https://github.com/SmartMoveSystems)
