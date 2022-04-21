#!/usr/bin/env python3
'''
Quickly implemented AES-GCM-NoPadding decryption tool that can decrypt Neo Backup encrypted files.
Feel free to use, study and extend it.
'''
import json
import os
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac

BACKUP_STAMP = '2022-04-20-22-59-54-061-user_0'
INPUT_FILEPATH = os.path.join(BACKUP_STAMP, 'data.tar.gz.enc')
PASSWORD = b'123456'
PBKDF_ITERATIONS = 2022
KEY_LEN = 32
FALLBACK_SALT = b'oandbackupx'

with open(BACKUP_STAMP + '.properties') as f:
    properties = json.load(f)
    iv_bytes = b''.join(map(lambda i: int(i).to_bytes(1, 'big', signed=True), properties['iv']))

key = pbkdf2_hmac(hash_name='sha256',
                  password=PASSWORD,
                  salt=, FALLBACK_SALT,
                  iterations=PBKDF_ITERATIONS,
                  dklen=KEY_LEN)
cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)
with open(INPUT_FILEPATH, 'rb') as input_file:
    with open(os.path.splitext(INPUT_FILEPATH)[0], 'wb') as output_file:
        # read the file's contents and discard the authentication tag
        # PyCryptdome doesn't check it implicitly unlike Java Crypto does.
        # It won't tell if it just decrypted garbage if you don't check the authenticity
        buffer_in = input_file.read()[:-16]
        buffer_out = cipher.decrypt(buffer_in)
        output_file.write(buffer_out)