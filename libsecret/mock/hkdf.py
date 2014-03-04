
# Upstream Author: Zooko O'Whielacronx <zooko@zooko.com>
#
#	Copyright:
#
#	You may use this package under the GNU General Public License, version
#	2 or, at your option, any later version.  You may use this package
#	under the Transitive Grace Period Public Licence, version 1.0 or, at
#	your option, any later version.  (You may choose to use this package
#	under the terms of either licence, at your option.)  See the file
#	COPYING.TESTS for the terms of the GNU General Public License, version 2.
#
#	The following licensing text applies to a subset of the Crypto++ source code
#	which is included in the pycryptopp source tree under the "embeddedcryptopp"
#	subdirectory.  That embedded subset of the Crypto++ source code is not used
#	when pycryptopp is built for Debian -- instead the --disable-embedded-cryptopp
#	option to "setup.py build" is used to for pycryptopp to build against the
#	system libcryptopp.

import hashlib, hmac
import math
from binascii import a2b_hex, b2a_hex

class HKDF(object):
    def __init__(self, ikm, L, salt=None, info="", digestmod = None):
        self.ikm = ikm
        self.keylen = L

        if digestmod is None:
            digestmod = hashlib.sha256

        if callable(digestmod):
            self.digest_cons = digestmod
        else:
            self.digest_cons = lambda d='':digestmod.new(d)
        self.hashlen = len(self.digest_cons().digest())

        if salt is None:
            self.salt = chr(0)*(self.hashlen)
        else:
            self.salt = salt

        self.info = info

    #extract PRK
    def extract(self):
        h = hmac.new(self.salt, self.ikm, self.digest_cons)
        self.prk = h.digest()
        return self.prk

    #expand PRK
    def expand(self):
        N = math.ceil(float(self.keylen)/self.hashlen)
        T = ""
        temp = ""
        i=0x01
        '''while len(T)<2*self.keylen :
            msg = temp
            msg += self.info
            msg += b2a_hex(chr(i))
            h = hmac.new(self.prk, a2b_hex(msg), self.digest_cons)
            temp = b2a_hex(h.digest())
            i += 1
            T += temp
       '''
        while len(T)<self.keylen :
            msg = temp
            msg += self.info
            msg += chr(i)
            h = hmac.new(self.prk, msg, self.digest_cons)
            temp = h.digest()
            i += 1
            T += temp

        self.okm = T[0:self.keylen]
        return self.okm

def new(ikm, L, salt=None, info="", digestmod = None):
    return HKDF(ikm, L,salt,info,digestmod)

def hkdf(ikm, length, salt=None, info=""):
	hk = HKDF(ikm, length ,salt,info)
	computedprk = hk.extract()
	return hk.expand()