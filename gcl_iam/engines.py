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

from gcl_iam import enforcers
from gcl_iam import exceptions
from gcl_iam import tokens


class IamEngine:

    def __init__(self, auth_token, algorithm, driver, enforcer=None):
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
            token_info=self._token_info
        )

        # Forbid requests without auth or without project scope
        if not self._introspection_info:
            raise exceptions.Unauthorized()

        self._enforcer = enforcer or enforcers.Enforcer(
            self._introspection_info["permissions"]
        )

    @property
    def token_info(self):
        return self._token_info

    def introspection_info(self):
        return self._introspection_info

    @property
    def enforcer(self):
        return self._enforcer
