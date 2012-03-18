#!/usr/bin/env python

import unittest

from gi.repository import MockService as Mock
from gi.repository import Secret, GLib

Mock.start("mock-service-normal.py")

STORE_SCHEMA = Secret.Schema.new("org.mock.Schema",
	Secret.SchemaFlags.NONE,
	{
		"number": Secret.SchemaAttributeType.INTEGER,
		"string": Secret.SchemaAttributeType.STRING,
		"even": Secret.SchemaAttributeType.BOOLEAN,
	}
)

class TestStore(unittest.TestCase):
	def setUp(self):
		Mock.start("mock-service-normal.py")

	def tearDown(self):
		Mock.stop()

	def testSynchronous(self):
		attributes = { "number": "9", "string": "nine", "even": "false" }

		password = Secret.password_lookup_sync(STORE_SCHEMA, attributes, None)
		self.assertEqual(None, password)

		stored = Secret.password_store_sync(STORE_SCHEMA, attributes, Secret.COLLECTION_DEFAULT,
		                                    "The number nine", "999", None)
		self.assertEqual(True, stored);

		password = Secret.password_lookup_sync(STORE_SCHEMA, attributes, None)
		self.assertEqual("999", password)

	def testAsynchronous(self):
		attributes = { "number": "888", "string": "eight", "even": "true" }

		password = Secret.password_lookup_sync(STORE_SCHEMA, attributes, None)
		self.assertEqual(None, password);

		loop = GLib.MainLoop(None, False)

		def on_result_ready(source, result, unused):
			loop.quit()
			stored = Secret.password_store_finish(result)
			self.assertEquals(True, stored)

		Secret.password_store(STORE_SCHEMA, attributes, None, "The number eight", "888",
		                      None, on_result_ready, None)

		loop.run()

		password = Secret.password_lookup_sync(STORE_SCHEMA, attributes, None)
		self.assertEqual("888", password)

if __name__ == '__main__':
		unittest.main()
