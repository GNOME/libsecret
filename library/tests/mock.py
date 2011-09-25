#!/usr/bin/env python

import os
import sys
import getopt
import unittest

import dbus
import dbus.service
import dbus.glib
import gobject

class NotSupported(dbus.exceptions.DBusException):
	def __init__(self, msg):
		dbus.exceptions.DBusException.__init__(self, msg, name="org.freedesktop.DBus.Error.NotSupported")

unique_identifier = 0
def next_identifier():
	global unique_identifier
	unique_identifier += 1
	return unique_identifier

class SecretSession(dbus.service.Object):
	def __init__(self, service, key):
		global unique_identifier
		self.key = key
		self.path = "/org/freedesktop/secrets/sessions/%d" % next_identifier()
		dbus.service.Object.__init__(self, service.bus_name, self.path)

class SecretService(dbus.service.Object):

	def __init__(self, name):
		self.bus_name = dbus.service.BusName(name, bus = dbus.SessionBus())
		dbus.service.Object.__init__(self, self.bus_name, '/org/freedesktop/secrets')
		self.sessions = { }

	def listen(self):
		loop = gobject.MainLoop()
		loop.run()

	@dbus.service.method('org.freedesktop.Secret.Service')
	def OpenSession(self, algorithm, input):
		assert type(algorithm) == dbus.String
		# assert type(input) == dbus.ByteArray

		if algorithm == "plain":
			session = SecretSession(self, None)
			self.sessions[session.path] = session
			return (dbus.String("", variant_level=1), session)

		elif algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7":
			raise NotSupported("algorithm %s is not supported" % algorithm)

		else:
			assert False, "algorithm %s not recognized" % algorithm

if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], "name", ["name="])
	except getopt.GetoptError, err:
		print str(err)
		sys.exit(2)
	name = 'org.freedesktop.Secret.MockService'
	for o, a in opts:
		if o in ("--name"):
			name = a
		else:
			assert False, "unhandled option"

	myservice = SecretService(name)
	myservice.listen()