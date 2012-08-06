/*
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

const Mock = imports.gi.MockService;
const Secret = imports.gi.SecretUnstable;
const GLib = imports.gi.GLib;

const JsUnit = imports.jsUnit;
const assertNotEquals = JsUnit.assertNotEquals;

Mock.start("mock-service-normal.py");

var service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, null);
var path = service.read_alias_dbus_path_sync("default", null);

/* Just running this without error is good enough for us to test the unstable gir */
assertNotEquals(path, null);

Mock.stop();
