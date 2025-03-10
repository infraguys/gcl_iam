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
    def __init__(self, *args, **kwargs):
        self.reset()

    def reset(self):
        self.user_uuid = "00000000-0000-0000-0000-000000000000"
        self.user_name = "admin"
        self.user_email = "admin@example.com"
        self.user_first_name = "Admin"
        self.user_last_name = "Only For Tests"
        self.project_id = None
        self.otp_verified = True
        self.permission_hash = "00000000-0000-0000-0000-000000000000"
        self.permissions = ["*.*.*"]

    def get_introspection_info(self, token_info):
        return {
            "user_info": {
                "uuid": self.user_uuid,
                "name": self.user_name,
                "first_name": self.user_first_name,
                "last_name": self.user_last_name,
                "email": self.user_email,
            },
            "project_id": self.project_id,
            "otp_verified": self.otp_verified,
            "permission_hash": self.permission_hash,
            "permissions": self.permissions,
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
