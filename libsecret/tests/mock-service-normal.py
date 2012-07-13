#!/usr/bin/env python

import mock

service = mock.SecretService()
service.add_standard_objects()
service.listen()