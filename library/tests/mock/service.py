#!/usr/bin/env python

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

import getopt
import os
import sys
import time
import unittest

import aes
import dh
import hkdf

import dbus
import dbus.service
import dbus.glib
import gobject

COLLECTION_PREFIX = "/org/freedesktop/secrets/collection/"

bus_name = 'org.freedesktop.Secret.MockService'
objects = { }

class NotSupported(dbus.exceptions.DBusException):
	def __init__(self, msg):
		dbus.exceptions.DBusException.__init__(self, msg, name="org.freedesktop.DBus.Error.NotSupported")

class InvalidArgs(dbus.exceptions.DBusException):
	def __init__(self, msg):
		dbus.exceptions.DBusException.__init__(self, msg, name="org.freedesktop.DBus.Error.InvalidArgs")

class IsLocked(dbus.exceptions.DBusException):
	def __init__(self, msg):
		dbus.exceptions.DBusException.__init__(self, msg, name="org.freedesktop.Secret.Error.IsLocked")

unique_identifier = 0
def next_identifier():
	global unique_identifier
	unique_identifier += 1
	return unique_identifier

def hex_encode(string):
	return "".join([hex(ord(c))[2:].zfill(2) for c in string])


class PlainAlgorithm():
	def negotiate(self, service, sender, param):
		if type (param) != dbus.String:
			raise InvalidArgs("invalid argument passed to OpenSession")
		session = SecretSession(service, sender, self, None)
		return (dbus.String("", variant_level=1), session)

	def encrypt(self, key, data):
		return ("", data)


class AesAlgorithm():
	def negotiate(self, service, sender, param):
		if type (param) != dbus.ByteArray:
			raise InvalidArgs("invalid argument passed to OpenSession")
		privat, publi = dh.generate_pair()
		peer = dh.bytes_to_number(param)
		# print "mock publi: ", hex(publi)
		# print " mock peer: ", hex(peer)
		ikm = dh.derive_key(privat, peer)
		# print "  mock ikm: ", hex_encode(ikm)
		key = hkdf.hkdf(ikm, 16)
		# print "  mock key: ", hex_encode(key)
		session = SecretSession(service, sender, self, key)
		return (dbus.ByteArray(dh.number_to_bytes(publi), variant_level=1), session)

	def encrypt(self, key, data):
		key = map(ord, key)
		data = aes.append_PKCS7_padding(data)
		keysize = len(key)
		iv = [ord(i) for i in os.urandom(16)]
		mode = aes.AESModeOfOperation.modeOfOperation["CBC"]
		moo = aes.AESModeOfOperation()
		(mode, length, ciph) = moo.encrypt(data, mode, key, keysize, iv)
		return ("".join([chr(i) for i in iv]),
		        "".join([chr(i) for i in ciph]))


class SecretPrompt(dbus.service.Object):
	def __init__(self, service, sender, prompt_name=None, delay=0,
	             dismiss=False, result=dbus.String("", variant_level=1),
	             action=None):
		self.sender = sender
		self.service = service
		self.delay = 0
		self.dismiss = False
		self.result = result
		self.action = action
		self.completed = False
		if prompt_name:
			self.path = "/org/freedesktop/secrets/prompts/%s" % prompt_name
		else:
			self.path = "/org/freedesktop/secrets/prompts/p%d" % next_identifier()
		dbus.service.Object.__init__(self, service.bus_name, self.path)
		service.add_prompt(self)
		assert self.path not in objects
		objects[self.path] = self

	def _complete(self):
		if self.completed:
			return
		self.completed = True
		self.Completed(self.dismiss, self.result)
		self.remove_from_connection()

	@dbus.service.method('org.freedesktop.Secret.Prompt')
	def Prompt(self, window_id):
		if self.action:
			self.action()
		gobject.timeout_add(self.delay * 1000, self._complete)

	@dbus.service.method('org.freedesktop.Secret.Prompt')
	def Dismiss(self):
		self._complete()

	@dbus.service.signal(dbus_interface='org.freedesktop.Secret.Prompt', signature='bv')
	def Completed(self, dismiss, result):
		pass


class SecretSession(dbus.service.Object):
	def __init__(self, service, sender, algorithm, key):
		self.sender = sender
		self.service = service
		self.algorithm = algorithm
		self.key = key
		self.path = "/org/freedesktop/secrets/sessions/%d" % next_identifier()
		dbus.service.Object.__init__(self, service.bus_name, self.path)
		service.add_session(self)
		objects[self.path] = self

	def encode_secret(self, secret, content_type):
		(params, data) = self.algorithm.encrypt(self.key, secret)
		# print "   mock iv: ", hex_encode(params)
		# print " mock ciph: ", hex_encode(data)
		return dbus.Struct((self.path, dbus.ByteArray(params), dbus.ByteArray(data),
		                    dbus.String(content_type)), signature="oayays")

	@dbus.service.method('org.freedesktop.Secret.Session')
	def Close(self):
		self.remove_from_connection()
		self.service.remove_session(self)


class SecretItem(dbus.service.Object):
	def __init__(self, collection, identifier, label="Item", attributes={ },
	             secret="", confirm=False, content_type="text/plain"):
		self.collection = collection
		self.identifier = identifier
		self.label = label
		self.secret = secret
		self.attributes = attributes
		self.content_type = content_type
		self.locked = collection.locked
		self.path = "%s/%s" % (collection.path, identifier)
		self.confirm = confirm
		dbus.service.Object.__init__(self, collection.service.bus_name, self.path)
		collection.items[identifier] = self
		objects[self.path] = self

	def match_attributes(self, attributes):
		for (key, value) in attributes.items():
			if not self.attributes.get(key) == value:
				return False
		return True

	def perform_delete(self):
		del self.collection.items[self.identifier]
		del objects[self.path]

	@dbus.service.method('org.freedesktop.Secret.Item', sender_keyword='sender')
	def GetSecret(self, session_path, sender=None):
		session = objects.get(session_path, None)
		if not session or session.sender != sender:
			raise InvalidArgs("session invalid: %s" % session_path) 
		if self.locked:
			raise IsLocked("secret is locked: %s" % self.path)
		return session.encode_secret(self.secret, self.content_type)

	@dbus.service.method('org.freedesktop.Secret.Item', sender_keyword='sender')
	def Delete(self, sender=None):
		if self.confirm:
			prompt = SecretPrompt(self.collection.service, sender,
			                      dismiss=False, action=self.perform_delete)
			return dbus.ObjectPath(prompt.path)
		else:
			self.perform_delete()
			return dbus.ObjectPath("/")


class SecretCollection(dbus.service.Object):
	def __init__(self, service, identifier, label="Collection", locked=False):
		self.service = service
		self.identifier = identifier
		self.label = label
		self.locked = locked
		self.items = { }
		self.path = "%s%s" % (COLLECTION_PREFIX, identifier)
		dbus.service.Object.__init__(self, service.bus_name, self.path)
		service.collections[identifier] = self
		objects[self.path] = self

	def search_items(self, attributes):
		results = []
		for item in self.items.values():
			if item.match_attributes(attributes):
				results.append(item)
		return results


class SecretService(dbus.service.Object):

	algorithms = {
		'plain': PlainAlgorithm(),
		"dh-ietf1024-sha256-aes128-cbc-pkcs7": AesAlgorithm(),
	}

	def __init__(self, name=None):
		if name == None:
			name = bus_name
		bus = dbus.SessionBus()
		self.bus_name = dbus.service.BusName(name, allow_replacement=True, replace_existing=True)
		dbus.service.Object.__init__(self, self.bus_name, '/org/freedesktop/secrets')
		self.sessions = { }
		self.prompts = { }
		self.collections = { }

		def on_name_owner_changed(owned, old_owner, new_owner):
			if not new_owner:
				for session in list(self.sessions.get(old_owner, [])):
					session.Close()

		bus.add_signal_receiver(on_name_owner_changed,
		                        'NameOwnerChanged',
		                        'org.freedesktop.DBus')

	def add_standard_objects(self):
		collection = SecretCollection(self, "collection", locked=False)
		SecretItem(collection, "item_one", attributes={ "number": "1", "string": "one", "parity": "odd" }, secret="uno")
		SecretItem(collection, "item_two", attributes={ "number": "2", "string": "two", "parity": "even" }, secret="dos")
		SecretItem(collection, "item_three", attributes={ "number": "3", "string": "three", "parity": "odd" }, secret="tres")

		collection = SecretCollection(self, "second", locked=True)
		SecretItem(collection, "item_one", attributes={ "number": "1", "string": "one", "parity": "odd" })
		SecretItem(collection, "item_two", attributes={ "number": "2", "string": "two", "parity": "even" })
		SecretItem(collection, "item_three", attributes={ "number": "3", "string": "three", "parity": "odd" })
	
	def listen(self):
		loop = gobject.MainLoop()
		loop.run()

	def add_session(self, session):
		if session.sender not in self.sessions:
			self.sessions[session.sender] = []
		self.sessions[session.sender].append(session)

	def remove_session(self, session):
		self.sessions[session.sender].remove(session)

	def add_prompt(self, prompt):
		if prompt.sender not in self.prompts:
			self.prompts[prompt.sender] = []
		self.prompts[prompt.sender].append(prompt)

	def remove_prompt (self, prompt):
		self.prompts[prompt.sender].remove(prompt)

	def find_item(self, object):
		if object.startswith(COLLECTION_PREFIX):
			parts = object[len(COLLECTION_PREFIX):].split("/", 1)
			if len(parts) == 2 and parts[0] in self.collections:
				return self.collections[parts[0]].get(parts[1], None)
		return None

	@dbus.service.method('org.freedesktop.Secret.Service', byte_arrays=True, sender_keyword='sender')
	def OpenSession(self, algorithm, param, sender=None):
		assert type(algorithm) == dbus.String

		if algorithm not in self.algorithms:
			raise NotSupported("algorithm %s is not supported" % algorithm)

		return self.algorithms[algorithm].negotiate(self, sender, param)

	@dbus.service.method('org.freedesktop.Secret.Service')
	def SearchItems(self, attributes):
		locked = [ ]
		unlocked = [ ]
		items = [ ]
		for collection in self.collections.values():
			items = collection.search_items(attributes)
			if collection.locked:
				locked.extend(items)
			else:
				unlocked.extend(items)
		return (dbus.Array(unlocked, "o"), dbus.Array(locked, "o"))

	@dbus.service.method('org.freedesktop.Secret.Service', sender_keyword='sender')
	def GetSecrets(self, item_paths, session_path, sender=None):
		session = objects.get(session_path, None)
		if not session or session.sender != sender:
			raise InvalidArgs("session invalid: %s" % session_path) 
		results = dbus.Dictionary(signature="o(oayays)")
		for item_path in item_paths:
			item = objects.get(item_path, None)
			if item and not item.locked:
				results[item_path] = item.GetSecret(session_path, sender)
		return results


def parse_options(args):
	global bus_name
	try:
		opts, args = getopt.getopt(args, "name", ["name="])
	except getopt.GetoptError, err:
		print str(err)
		sys.exit(2)
	for o, a in opts:
		if o in ("--name"):
			bus_name = a
		else:
			assert False, "unhandled option"
	return args

parse_options(sys.argv[1:])
