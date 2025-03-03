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
    enforcer = Enforcer(perms)

    assert isinstance(enforcer._perms, collections.defaultdict)

    # Test with empty perms list
    enforcer_empty = Enforcer([])

    assert len(enforcer_empty._perms) == 0


def test_load_perms():
    enforcer = Enforcer(perms)

    expected_permissions = {
        "service": {"resource": set(["action"])},
        "genesis_core": {"vm": set(["create", "*"])},
    }

    assert enforcer._perms == expected_permissions


def test_enforce_allow():
    enforcer = Enforcer(perms)

    result = enforcer.enforce("service.resource.action")

    assert result == Grant.ALLOW


def test_enforce_admin():
    enforcer = Enforcer(admin_perm)

    result = enforcer.enforce("service.resource.mega")

    assert result == Grant.ADMIN


def test_enforce_deny():
    enforcer = Enforcer(perms)

    result = enforcer.enforce("service.resource.other")

    assert result == Grant.DENY


def test_enforce_comparable_permission():
    enforcer = Enforcer(perms)

    result = enforcer.enforce("genesis_core.vm.create")

    assert result > Grant.ALLOW


def test_error_raising_on_denied_rule():
    enforcer = Enforcer(perms)

    with pytest.raises(exceptions.PolicyNotAuthorized) as excinfo:
        enforcer.enforce("service.resource.other", do_raise=True)

    assert "service.resource.other" in str(excinfo.value)


def test_error_raising_on_deny_rule_without_exception():
    enforcer = Enforcer(perms)

    result = enforcer.enforce(
        "service.resource.other",
        do_raise=False,
        exc=exceptions.PolicyNotAuthorized,
    )

    assert result == Grant.DENY


def test_enforce_multiple_permissions():
    enforcer = Enforcer(perms)

    result = enforcer.enforce("genesis_core.vm.*")

    assert result == Grant.ADMIN
