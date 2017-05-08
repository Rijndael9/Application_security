# -*- coding: utf-8 -*-
"""
Created on Wed Mar  1 13:27:59 2017

@author: Tina
"""
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto import Random
import timeit

def AAES():
    obj = AES.new('1000000000000000', AES.MODE_CBC, 'This is an IV456')
    message = "The answer is no"
    ciphertext = obj.encrypt(message)
    obj2 = AES.new('This is a key123543', AES.MODE_CBC, 'This is an IV456')
    obj2.decrypt(ciphertext)
    print('Haslo zaszyfrowane AES: ', ciphertext)
def DESa():
    des = DES.new('10000000', DES.MODE_ECB) #8 битовый ключ
    cipher_text = des.encrypt('10000000')
    print('Haslo zaszyfrowane DES: ' ,cipher_text)
    decdes = des.decrypt(cipher_text)
def RSAa():
    plaintxt = b'password'
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey()
    enc = public_key.encrypt(plaintxt, 32) #пароль зашифрован
    print ("Haslo zaszyfrowane RSA: ", enc)
    decrsa = key.decrypt(enc) # decription plaintxt == decrsa
    
if __name__ == "__main__":
     print ('Time for AES: ', timeit.timeit("AAES()","from __main__ import AAES",number=1))  
     print ('Time for DES:', timeit.timeit("DESa()","from __main__ import DESa",number=1))
     print ('Time for RSA: ', timeit.timeit("RSAa()","from __main__ import RSAa",number=1))