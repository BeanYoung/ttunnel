#!/usr/bin/python
# -*- coding: utf-8 -*-

from hashlib import md5

from Crypto.Cipher import AES


key = '123456'
key = md5(key).hexdigest()


ec = AES.new(key, AES.MODE_CFB, key[:16])
dc = AES.new(key, AES.MODE_CFB, key[:16])


for i in range(100):
    cipher_text = ec.encrypt('1234')
    print len(cipher_text)
    dc.decrypt(cipher_text)
