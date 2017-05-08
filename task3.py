# -*- coding: utf-8 -*-
"""
Created on Tue Mar  7 21:55:24 2017

@author: Tina
"""

#import hashlib
#import bcrypt
from Crypto.Hash import SHA256
from Crypto.Hash import MD5
import timeit
from Crypto.PublicKey import RSA
import hashlib, binascii


def sha256a():
    string = b'hawa nagilla'
    sha256 = hashlib.sha256(string)
    hash = SHA256.new()
    hash.update(b'This is')
    hash.update(b'hash')
    sha256 = hash.hexdigest()
#    print ('SHA256: ', sha256)
    print('Hash block size SHA256: ',hash.block_size)

def md5a():
    string = b'hawa nagilla'
    md5 = hashlib.md5(string)
    h = MD5.new()
    h.update(b'This is')
    h.update(b'hash')
    md5 = h.hexdigest()
#    print ('MD5: ', md5)
    print('Hash block size MD5: ',h.block_size)


def PBKDF2():
    dk = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000) #name, password, salt, rounds, dklen=None
    print(binascii.hexlify(dk)) # возвращает двичное представление шестнадцатеричных данных. Строка вдвое длиннее от данных
#    string = b'hawa nagilla' https://docs.python.org/3/library/hashlib.html
#    # с раднлмной солью хешируем парольпервый раз
#    hashed = bcrypt.hashpw(string, bcrypt.gensalt())
#    hashed = bcrypt.hashpw(string, bcrypt.gensalt(10))
#    if bcrypt.hashpw(string, hashed) == hashed:
#        print ("It matches", hashed)
#    else:
#        print ("It does not match", hashed)
    
if __name__ == "__main__":
    print ('Time for SHA256: ', timeit.timeit("sha256a()","from __main__ import sha256a",number=1))
    print ('Time for MD5: ', timeit.timeit("md5a()","from __main__ import md5a",number=1))
    print ('Time for PBKDF: ', timeit.timeit("PBKDF2()","from __main__ import PBKDF2",number=1))
