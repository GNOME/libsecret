#!/usr/bin/env python

import unittest

from gi.repository import MockService as Mock
from gi.repository import Secret, SecretUnstable, GLib

STORE_SCHEMA = Secret.Schema.new("org.mock.Schema",
	Secret.SchemaFlags.NONE,
	{
		"number": Secret.SchemaAttributeType.INTEGER,
		"string": Secret.SchemaAttributeType.STRING,
		"even": Secret.SchemaAttributeType.BOOLEAN,
	}
)

class TestLookup(unittest.TestCase):
	def setUp(self):
		Mock.start("mock-service-normal.py")

	def tearDown(self):
		SecretUnstable.Service.disconnect()
		Mock.stop()

	def testSynchronous(self):
		password = Secret.password_lookup_sync (STORE_SCHEMA, { "number": "1", "even": "false" }, None)
		self.assertEqual("111", password)

	def testSyncNotFound(self):
		password = Secret.password_lookup_sync (STORE_SCHEMA, { "number": "5", "even": "true" }, None)
		self.assertEqual(None, password)

	def testAsynchronous(self):
		loop = GLib.MainLoop(None, False)

		def on_result_ready(source, result, unused):
			loop.quit()
			password = Secret.password_lookup_finish(result)
			self.assertEquals("222", password)

		Secret.password_lookup (STORE_SCHEMA, { "number": "2", "string": "two" },
		                        None, on_result_ready, None)

		loop.run()

	def testAsyncNotFound(self):
		loop = GLib.MainLoop(None, False)

		def on_result_ready(source, result, unused):
			loop.quit()
			password = Secret.password_lookup_finish(result)
			self.assertEquals(None, password)

		Secret.password_lookup (STORE_SCHEMA, { "number": "7", "string": "five" },
		                        None, on_result_ready, None)

		loop.run()

if __name__ == '__main__':
		unittest.main()
