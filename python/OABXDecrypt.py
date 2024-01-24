#!/usr/bin/env python3
"""
Quickly implemented AES-GCM-NoPadding decryption tool that can decrypt Neo Backup encrypted files.
Feel free to use, study and extend it.

License: AGPL-3.0

Author(s): https://github.com/Tiefkuehlpizze
           https://github.com/Jakeler
           https://github.com/sylikc

"""
# standard
import json
import os
import argparse
from pathlib import Path
from hashlib import pbkdf2_hmac


# pycryptodome
from Crypto.Cipher import AES



def oabxdecrypt(enc_path: Path,
                prop_path: Path,
                out_path: Path,
                password=b"",
                salt=None,
                key_len: int = None,
                pbkdf_iterations: int = None):

    # put these constants inside the method instead of outside,
    # making this method more copy/pastable
    PBKDF_ITERATIONS = 2020
    KEY_LEN = 32
    FALLBACK_SALT = b"oandbackupx"


    # set defaults on all None params
    p_salt = salt or FALLBACK_SALT
    p_keylen = key_len or KEY_LEN
    p_iterations = pbkdf_iterations or PBKDF_ITERATIONS

    # open properties file to extract initialization vector
    with open(prop_path, "r") as f:
        properties = json.load(f)
        iv_bytes = b"".join(map(lambda i: int(i).to_bytes(1, "big", signed=True), properties["iv"]))


    # build the key
    key = pbkdf2_hmac(hash_name="sha256",
                      password=password,
                      salt=p_salt,
                      iterations=p_iterations,
                      dklen=p_keylen)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)


    # read entire file into memory
    with open(enc_path, "rb") as input_file:
        input_bytes = input_file.read()


    # splice out the two parts
    ciphertext = input_bytes[:-16]
    tag = input_bytes[-16:]
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # write to file, removing the ".enc" extension
    with open(out_path, "wb") as output_file:
        output_file.write(plaintext)






def main():

    help_text: str = """
OABX Decrypt (NeoBackup Decrypt)

Reference Python implementation

Examples:
  {f} --file somewhere/data.tar.gz.enc --propfile somewhereelse/user.properties --passfile filewithpass.txt
  {f} --file somewhere/data.tar.gz.enc --propfile somewhereelse/user.properties --output /tmp
  {f} --bulk backupdir/copied/from/storage --output /tmp --passfile filewithpass.txt

Errorlevel:
  0 = success
  1 = error (crashes)
""".format(f=Path(__file__).name)

    parser = argparse.ArgumentParser(description=help_text, formatter_class=argparse.RawTextHelpFormatter)

    # rudimentary creation of args, without getting too fancy with groups
    # correct param arguments are checked later, without enforcing complex required combinations with argparse

    parser.add_argument("-f", "--file",
                        type=str,
                        metavar="ENCRYPTED_FILE",
                        help="path/to/encrypted/backup.tar.gz.enc")
    parser.add_argument("-p", "--propfile",
                        type=str,
                        metavar="PROPERTIES_FILE",
                        help="path/to/propfile.properties")



    parser.add_argument("--bulk",
                        type=str,
                        metavar="BASE_DIR",
                        help="Base dir to start bulk operation (unmodified NeoBackup structure), find all .properties files and decrypt all *.enc")


    parser.add_argument("--passfile",
                        type=str,
                        metavar="PASSWORD_FILE",
                        help="Specify a file with a password in it.  Reads file verbatim, so make sure there's no endlines!")
    parser.add_argument("--password",
                        type=str,
                        help="Specify a password on command line (insecure, not recommended).  By default, will read NB_PASSWORD environment variable for password")


    parser.add_argument("-o", "--output", type=str, metavar="PATH", help="Output directory.  Default is same base path as --file")





    # parse command line
    args = parser.parse_args()


    # get argument or environment variable
    if args.passfile:
        # open and read password file
        with open(args.passfile, "rb") as f:
            password_b = f.read()
    else:
        password = args.password or os.environ.get("NB_PASSWORD", "")

        # turn into bytes
        password_b = password.encode()



    if args.file and args.propfile and not args.bulk:
        # valid combo for running on single file

        # does not error check paths for existence yet
        encfile = Path(args.file)
        propfile = Path(args.propfile)
        outfile = encfile.with_suffix("")

        if args.output:
            # replace with the proper output path for the file
            outfile = Path(args.output) / outfile.name

        print(f"enc file:  {encfile}")
        print(f"prop file: {propfile}")
        print(f"out file:  {outfile}")

        oabxdecrypt(encfile,
                    propfile,
                    outfile,
                    password=password_b)

    elif args.bulk and not (args.file or args.propfile):
        # search and decrypt all, crashes on first bad decryption
        bulk_path = Path(args.bulk)

        if args.output:
            output_path = Path(args.output)
            # must exist
            if not output_path.is_dir():
                raise NotADirectoryError
        else:
            output_path = None


        if not bulk_path.is_dir():
            raise NotADirectoryError

        # recursive search through the bulk_path
        for propfile in bulk_path.glob("**/*.properties"):
            # properties file found, search for encrypted files at that level

            # the directory is named the same as the properties file with ".properties"
            # only one flat level of files
            for encfile in propfile.with_suffix("").glob("*.enc"):
                # remove .enc for output file
                outfile = encfile.with_suffix("")

                if output_path:
                    # replace with output path in the same relative path in basedir
                    relative = outfile.relative_to(bulk_path)
                    outfile = output_path / relative

                    # create the subdir structure for custom output
                    outfile.parent.mkdir(parents=True, exist_ok=True)

                print(f"enc file:  {encfile}")
                print(f"prop file: {propfile}")
                print(f"out file:  {outfile}")

                oabxdecrypt(encfile,
                            propfile,
                            outfile,
                            password=password_b)


    else:
        raise ValueError("Invalid combination of parameters")


    # MAC check failed means a bad file or wrong password, etc




if __name__ == "__main__":
    main()
