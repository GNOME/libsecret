#!/usr/bin/env python

import mock

service = mock.SecretService()

collection = mock.SecretCollection(service, "collection", locked=False)
mock.SecretItem(collection, "item_one", attributes={ "number": "1", "string": "one", "parity": "odd" })
mock.SecretItem(collection, "item_two", attributes={ "number": "2", "string": "two", "parity": "even" })
mock.SecretItem(collection, "item_three", attributes={ "number": "3", "string": "three", "parity": "odd" })

collection = mock.SecretCollection(service, "second", locked=True)
mock.SecretItem(collection, "item_one", attributes={ "number": "1", "string": "one", "parity": "odd" })
mock.SecretItem(collection, "item_two", attributes={ "number": "2", "string": "two", "parity": "even" })
mock.SecretItem(collection, "item_three", attributes={ "number": "3", "string": "three", "parity": "odd" })

service.listen()