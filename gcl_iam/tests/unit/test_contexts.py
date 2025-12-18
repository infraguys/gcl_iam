#    Copyright 2025 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import unittest.mock as mock

import gcl_iam.contexts as contexts


def test_get_real_url_with_prefix_no_port_in_host_url() -> None:
    req = mock.Mock()
    req.headers = {}
    req.host_url = "https://example.com/"

    ctx = contexts.GenesisCoreAuthContext(req)
    assert ctx.get_real_url_with_prefix() == "https://example.com"


def test_get_real_url_with_prefix_forwarded_no_port_header() -> None:
    req = mock.Mock()
    req.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "example.com",
        "X-Forwarded-Prefix": "/api/",
    }
    req.host_url = "http://internal.local/"

    ctx = contexts.GenesisCoreAuthContext(req)
    assert ctx.get_real_url_with_prefix() == "https://example.com/api"


def test_get_real_url_with_prefix_host_url_with_port() -> None:
    req = mock.Mock()
    req.headers = {}
    req.host_url = "http://example.com:8080/"

    ctx = contexts.GenesisCoreAuthContext(req)
    assert ctx.get_real_url_with_prefix() == "http://example.com:8080"


def test_get_real_url_with_prefix_forwarded_port_header() -> None:
    req = mock.Mock()
    req.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "example.com",
        "X-Forwarded-Port": "8443",
        "X-Forwarded-Prefix": "/api/",
    }
    req.host_url = "http://internal.local:8080/"

    ctx = contexts.GenesisCoreAuthContext(req)
    assert ctx.get_real_url_with_prefix() == "https://example.com:8443/api"
