import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import binascii
import os
import time
from algorithms import e_cbc,d_cbc,e_cfb,d_cfb,e_ctr,d_ctr,e_ecb,d_ecb,e_ofb,d_ofb
from block_ciphers import ctre,ctrd,cbcd,cbce,cfbe,cfbd,ofbe,ofbd,ecbe,ecbd

cbce()
cbcd()

ctre()
ctrd()

cfbe()
cfbd()

ofbe()
ofbd()

ecbe()
ecbd()

