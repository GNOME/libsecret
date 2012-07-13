#!/usr/bin/env python

import dbus
import mock
import sys

service = mock.SecretService()
service.add_standard_objects()

collection = mock.SecretCollection(service, "todelete", locked=False)
mock.SecretItem(collection, "item", attributes={ "number": "1", "string": "one", "even": "false" }, secret="uno")
mock.SecretItem(collection, "confirm", attributes={ "number": "2", "string": "two", "even": "true" }, secret="dos", confirm=True)

collection = mock.SecretCollection(service, "twodelete", locked=True)
mock.SecretItem(collection, "locked", attributes={ "number": "3", "string": "three", "even": "false" }, secret="tres")

service.listen()