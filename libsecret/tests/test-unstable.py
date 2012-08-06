#!/usr/bin/env python

#
# Copyright 2012 Red Hat Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the licence or (at
# your option) any later version.
#
# See the included COPYING file for more information.
#

import unittest

from gi.repository import MockService as Mock
from gi.repository import SecretUnstable as Secret, GLib

class TestStore(unittest.TestCase):
	def setUp(self):
		Mock.start("mock-service-normal.py")

	def tearDown(self):
		Secret.Service.disconnect()
		Mock.stop()

	def testSynchronous(self):
		service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, None);
		path = service.read_alias_dbus_path_sync("default", None);

		# Just running this without error is good enough for us to test the unstable gir
		self.assertNotEqual(path, None);

if __name__ == '__main__':
		unittest.main()
