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
from enum import Enum
import logging

from gcl_iam import exceptions
from gcl_iam import rules


LOG = logging.getLogger(__name__)


class OrderedEnum(Enum):

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class BasicOrderedGrant(OrderedEnum):
    def __bool__(self):
        if self.value > 0:
            return True
        return False


class Grant(BasicOrderedGrant):

    DENY = 0
    # VIEWER = 1
    # REGULAR = 10
    ALLOW = 100


class PermissionLevel(collections.defaultdict):
    def get(self, key, default=None):
        if res := super().get("*", None):
            return res
        return super().get(key, default)

    def __getitem__(self, key):
        if res := super().get("*", None):
            return res
        return super().__getitem__(key)


class BasicPermission(set):
    def get_grant_level(self, name):
        if "*" in self:
            return Grant.ALLOW
        if name in self:
            return Grant.ALLOW
        return Grant.DENY


class Enforcer(object):
    """
    A class to enforce permissions based on a list of predefined permissions.

    This class is used to check whether a given action is authorized or not.
    It allows for flexible permission definitions and supports wildcard-based
    permissions.

    Attributes:
        perms (list): A list of strings defining the permissions. Each string
                      represents a permission in the format
                      "service.resource.action".
                      Wildcards are supported, such as "*", which can be used
                      to grant all actions for a resource.

    Examples:
        # Define permissions
        perms = [
            "service.resource.action",
            "genesis_core.vm.create",
            "genesis_core.vm.*",
            "*.*.*"  # It's equal to full admin without project filters!
        ]

        # Create an Enforcer instance with the defined permissions
        enforcer = Enforcer(perms)

        # Check if a permission is granted for a specific action
        result = enforcer.enforce("genesis_core.vm.create")
        print(result)  # Output: Grant.ALLOW

        # Check if a wildcard permission applies to a resource
        result = enforcer.enforce("genesis_core.*.action")
        print(result)  # Output: Grant.ALLOW
    """

    def __init__(
        self,
        perms,
        perm_class=BasicPermission,
        level_class=PermissionLevel,
    ):
        self._perms = level_class(lambda: level_class(perm_class))
        self._load_perms(perms)

    def _load_perms(self, perms):
        for p in perms:
            service, res, perm = p.split(".", maxsplit=2)
            # Add the rule to a list of perms
            self._perms[service][res].add(perm)

    def enforce_raw(self, rule, do_raise=False, exc=None):
        rule_obj = rules.Rule.from_raw(rule)
        return self.enforce(rule_obj, do_raise, exc)

    def enforce(self, rule, do_raise=False, exc=None):
        result = Grant.DENY
        if resource := self._perms.get(rule.service):
            if permission := resource.get(rule.res):
                result = permission.get_grant_level(rule.perm)

        if do_raise and not result:
            if exc:
                raise exc(rule=(".".join((rule.service, rule.res, rule.perm))))

            raise exceptions.PolicyNotAuthorized(
                rule=(".".join((rule.service, rule.res, rule.perm)))
            )

        return result
