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

import abc

import bazooka

from gcl_iam import exceptions


class AbstractAuthDriver(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_introspection_info(self, token_info):
        raise NotImplementedError("Not implemented")


class DummyDriver(AbstractAuthDriver):
    def get_introspection_info(self, token_info):
        return {
            "user_info": {
                "uuid": "00000000-0000-0000-0000-000000000000",
                "name": "admin",
                "first_name": "Admin",
                "last_name": "Only For Tests",
                "email": "admin@example.com",
            },
            "project_id": None,
            "otp_verified": True,
            "permission_hash": "00000000-0000-0000-0000-000000000000",
            "permissions": ["*.*.*"],
        }


class HttpDriver(AbstractAuthDriver):

    def __init__(self, default_timeout=5):
        super().__init__()
        self._client = bazooka.Client(default_timeout=default_timeout)

    def get_introspection_info(self, token_info):
        issuer_url = token_info.issuer_url
        introspection_url = f"{issuer_url}/actions/introspect"
        try:
            return self._client.get(
                introspection_url,
                headers={"Authorization": f"Bearer {token_info.token}"},
            ).json()
        except bazooka.exceptions.RequestError:
            raise exceptions.InvalidAuthTokenError()
