#!/usr/bin/env python

import unittest

from gi.repository import MockService as Mock
from gi.repository import SecretUnstable as Secret, GLib

class TestStore(unittest.TestCase):
	def setUp(self):
		Mock.start("mock-service-normal.py")

	def tearDown(self):
		Mock.stop()

	def testSynchronous(self):
		service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, None);
		path = service.read_alias_dbus_path_sync("default", None);

		# Just running this without error is good enough for us to test the unstable gir
		self.assertNotEqual(path, None);

if __name__ == '__main__':
		unittest.main()
