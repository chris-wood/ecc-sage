#!/usr/bin/env sage -python

import os
from sage.all import *
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class Params():
    def __init__(self):
        self.curve = EllipticCurve(GF(2**255-19), [0,486662,0,1,0])
        self.base = curve.gen(0)
        self.n = base.order()
        self.gen_random = lambda : random.randint(1, n - 1)

def derive_key(source):
    backend = default_backend()
    salt = ""
    info = "ecies"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info, backend=backend)
    key = hkdf.derive(source)
    return key

def encrypt(params, m, pub_key):
    r = params.gen_random()
    R = r * params.base
    p = r * pub_key
    kdf_source = p[0]
    key = derive_key(kdf_source)
    f = Fernet(key)
    return f.encrypt(m), R

def decrypt(params, ct, R, private_key):
    p = R * private_key
    kdf_source = p[0]
    key = derive_key(kdf_source)
    f = Fernet(key)
    return f.decrypt(m)

params = Params()
private_key = params.gen_random()
public_key = private_key * params.base

m = "hello, world"

ct, R = encrypt(params, m, public_key)
print ct
mprime = decrypt(params, ct, R, private_key)
print mprime    

