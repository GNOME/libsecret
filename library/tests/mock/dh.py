
# WARNING: This is for use in mock objects during testing, and NOT
# cryptographically secure or performant.

#
# Copyright 2011 Stef Walter
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2 of the licence or (at
# your option) any later version.
#
# See the included COPYING file for more information.
#

#
# Some utility functions from tlslite which is public domain
# Written by Trevor Perrin <trevp at trevp.net>
# http://trevp.net/tlslite/
#

import math
import random

PRIME = '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1' \
	'\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD' \
	'\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45' \
	'\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED' \
	'\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE6\x53\x81' \
	'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'

def num_bits(number):
	if number == 0:
		return 0
	s = "%x" % number
	return ((len(s)-1)*4) + \
	    {'0':0, '1':1, '2':2, '3':2,
	     '4':3, '5':3, '6':3, '7':3,
	     '8':4, '9':4, 'a':4, 'b':4,
	     'c':4, 'd':4, 'e':4, 'f':4,
	    }[s[0]]

def num_bytes(number):
	if number == 0:
		return 0
	bits = num_bits(number)
	return int(math.ceil(bits / 8.0))

def bytes_to_number(data):
	number = 0L
	multiplier = 1L
	for count in range(len(data) - 1, -1, -1):
		number += multiplier * ord(data[count])
		multiplier *= 256
	return number

def number_to_bytes(number):
	n_data = num_bytes(number)
	data = ['' for i in range(0, n_data)]
	for count in range(n_data - 1, -1, -1):
		data[count] = chr(number % 256)
		number >>= 8
	return "".join(data)

def generate_pair():
	prime = bytes_to_number (PRIME)
	base = 2
	# print "mock prime: ", hex(prime)
	# print " mock base: ", hex(base)
	bits = num_bits(prime)
	privat = 0
	while privat == 0:
		privat = random.getrandbits(bits - 1)
	publi = pow(base, privat, prime)
	return (privat, publi)

def derive_key(privat, peer):
	prime = bytes_to_number (PRIME)
	key = pow(peer, privat, prime)
	# print " mock ikm2: ", hex(key)
	return number_to_bytes(key)
