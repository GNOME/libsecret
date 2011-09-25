#!/usr/bin/env python

import mock

service = mock.SecretService()
service.algorithms = { "plain": mock.PlainAlgorithm() }
service.listen()