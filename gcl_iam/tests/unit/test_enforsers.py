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

import collections

import pytest
from gcl_iam.enforcers import Enforcer, Grant
from gcl_iam import exceptions

# Sample permissions data
perms = [
    "service.resource.action",
    "genesis_core.vm.create",
    "genesis_core.vm.*",
]

admin_perm = ["service.resource.action", "*.*.*"]


def test_enforcer_init():
    # Test default initialization
    enforcer = Enforcer(perms, service="genesis_core")

    assert isinstance(enforcer._perms, collections.defaultdict)

    # Test with empty perms list
    enforcer_empty = Enforcer([], service="genesis_core")

    assert len(enforcer_empty._perms) == 0


def test_load_perms():
    enforcer = Enforcer(perms, service="genesis_core")

    expected_permissions = {
        "service": {"resource": set(["action"])},
        "genesis_core": {"vm": set(["create", "*"])},
    }

    assert enforcer._perms == expected_permissions


def test_enforce_raw():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce_raw("service.resource.action")

    assert result == Grant.REGULAR


def test_enforce_allow():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce("resource", "action", service="service")

    assert result == Grant.REGULAR


def test_enforce_admin():
    enforcer = Enforcer(admin_perm, service="genesis_core")

    result = enforcer.enforce("resource", "mega")

    assert result == Grant.FULL


def test_enforce_deny():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce("resource", "other")

    assert result == Grant.DENY


def test_enforce_comparable_permission():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce_raw("genesis_core.vm.create")

    assert result > Grant.REGULAR


def test_error_raising_on_denied_rule():
    enforcer = Enforcer(perms, service="genesis_core")

    with pytest.raises(exceptions.PolicyNotAuthorized) as excinfo:
        enforcer.enforce("resource", "other", do_raise=True)

    assert "genesis_core.resource.other" in str(excinfo.value)


def test_error_raising_on_deny_rule_without_exception():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce(
        "resource",
        "other",
        do_raise=False,
        exc=exceptions.PolicyNotAuthorized,
    )

    assert result == Grant.DENY


def test_enforce_multiple_permissions():
    enforcer = Enforcer(perms, service="genesis_core")

    result = enforcer.enforce_raw("genesis_core.vm.*")

    assert result == Grant.FULL
