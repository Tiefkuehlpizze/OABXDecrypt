# Python implementation

Initial work done by [Tiefkuehlpizze](https://github.com/Tiefkuehlpizze) with
major updates by [Jakeler](https://github.com/Jakeler)


[sylikc](https://github.com/sylikc) making some interface improvements on usability (use on different files without having to update the py file), convert to Python3 code, write this README, etc.

Improvements should make it easier to use the reference implementation in a portable way (broke down code into methods, etc)


## Prerequisites

Install [PyCryptodome](https://www.pycryptodome.org)
```shell
python -m pip install -r requirements.txt
```

## Usage

Same as the java application:

Run it like this:
```shell
# type your password into a variable (it won't be echoed) and you only have to do it once per shell session
read -s NB_PASSWORD && export NB_PASSWORD
# to decrypt OABX 6 backups (untested)
# to decrypt NeoBackup 7-8 backups
python3 OABXDecrypt.py --file "path/to/encrypted/backup.tar.gz.enc" -propfile "path/to/propfile.properties"

# Other options to provide the password
# Read the password from a file (maybe unsecure)
python3 OABXDecrypt.py --passfile "path/to/passfile" --file "path/to/encrypted/backup.tar.gz.env" --propfile "path/to/propfile.properties"
# or use your password as argument (unsecure)
python3 OABXDecrypt.py --password "YourSecretPassword" --file "path/to/encrypted/backup.tar.gz.env" --propfile "path/to/propfile.properties"
```

