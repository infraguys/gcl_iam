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

import uuid as sys_uuid

from gcl_iam import enforcers
from gcl_iam import exceptions
from gcl_iam import tokens


class UserInfo:
    def __init__(self, info):
        self._info = info

    @property
    def uuid(self):
        return self._info["uuid"]

    @property
    def name(self):
        return self._info["name"]

    @property
    def first_name(self):
        return self._info["first_name"]

    @property
    def last_name(self):
        return self._info["last_name"]

    @property
    def email(self):
        return self._info["email"]


class IntrospectionInfo:
    def __init__(self, info):
        self._info = info

    @property
    def user_info(self):
        return UserInfo(info=self._info["user_info"])

    @property
    def project_id(self):
        value = self._info["project_id"]
        return sys_uuid.UUID(value) if value else None

    @property
    def otp_verified(self):
        return self._info["otp_verified"]

    @property
    def permissions(self):
        return self._info["permissions"][:]


class IamEngine:

    def __init__(
        self, auth_token, algorithm, driver, enforcer=None, otp_code=None
    ):
        super().__init__()
        self._token_info = tokens.AuthToken(
            auth_token,
            algorithm,
            ignore_audience=True,
            ignore_expiration=False,
            verify=True,
        )
        self._driver = driver
        self._introspection_info = self._driver.get_introspection_info(
            token_info=self._token_info,
            otp_code=otp_code,
        )

        # Forbid requests without auth or without project scope
        if not self._introspection_info:
            raise exceptions.Unauthorized()

        self._enforcer = enforcer or enforcers.Enforcer(
            self._introspection_info["permissions"]
        )

        self._introspection_info["otp_enabled"] = self._token_info.otp_enabled

    @property
    def token_info(self):
        return self._token_info

    def introspection_info(self):
        return self._introspection_info

    def get_introspection_info(self):
        return IntrospectionInfo(info=self._introspection_info)

    @property
    def enforcer(self):
        return self._enforcer
