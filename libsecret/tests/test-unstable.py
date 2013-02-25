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
from gi.repository import SecretUnstable, Secret, GLib

EXAMPLE_SCHEMA = Secret.Schema.new('org.mock.type.Store',
	Secret.SchemaFlags.NONE,
	{
		'number': Secret.SchemaAttributeType.INTEGER,
		'string': Secret.SchemaAttributeType.STRING,
		'even': Secret.SchemaAttributeType.BOOLEAN,
	}
)

attributes = {
	'number': '8',
	'string': 'eight',
	'even': 'true'
}

class TestStore(unittest.TestCase):
	def setUp(self):
		Mock.start("mock-service-normal.py")

	def tearDown(self):
		SecretUnstable.Service.disconnect()
		Mock.stop()

	def testSynchronous(self):
		service = SecretUnstable.Service.get_sync(SecretUnstable.ServiceFlags.NONE, None);
		path = service.read_alias_dbus_path_sync("default", None);

		# Just running this without error is good enough for us to test the unstable gir
		self.assertNotEqual(path, None);

	def testValueGet(self):
		Secret.password_store_sync(EXAMPLE_SCHEMA, attributes, Secret.COLLECTION_DEFAULT,
		                           'the label', 'the password', None)

		service = SecretUnstable.Service.get_sync(SecretUnstable.ServiceFlags.NONE, None)
		items = service.search_sync(EXAMPLE_SCHEMA, { 'even': 'true' },
		                                   SecretUnstable.SearchFlags.ALL | SecretUnstable.SearchFlags.LOAD_SECRETS,
		                                   None)

		item = items[0]
		item_secret = item.get_secret()
		self.assertEqual(item_secret.get(), "the password")

if __name__ == '__main__':
		unittest.main()
