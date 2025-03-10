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

import datetime
import os
import uuid

import bazooka
from bazooka import common
import jwt


SECRET = "secret"


class GenesisCoreAuth:

    def __init__(
        self,
        username: str,
        password: str,
        client_uuid: str = "00000000-0000-0000-0000-000000000000",
        client_id: str = "GenesisCoreClientId",
        client_secret: str = "GenesisCoreClientSecret",
    ):
        super().__init__()
        self._username = username
        self._password = password
        self._client_uuid = client_uuid
        self._client_id = client_id
        self._client_secret = client_secret

    def get_token_url(self, endpoint="http://localhost:11010/v1/"):
        return (
            f"{common.force_last_slash(endpoint)}iam/clients/"
            f"{self._client_uuid}/actions/get_token/invoke"
        )

    def get_password_auth_params(self):
        return {
            "grant_type": "password",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "username": self._username,
            "password": self._password,
        }

    def get_refresh_token_auth_params(self, refresh_token):
        return {
            "grant_type": "refresh_token",
            "refresh_token": "refresh_token",
        }


class GenesisCoreTestRESTClient(common.RESTClientMixIn):

    def __init__(self, endpoint: str, auth: GenesisCoreAuth, timeout: int = 5):
        super().__init__()
        self._endpoint = endpoint
        self._timeout = timeout
        self._auth = auth
        self._client = bazooka.Client(default_timeout=timeout)
        self._auth_cache = None

    def authenticate(self):
        if not self._auth_cache:
            self._auth_cache = self._client.post(
                self._auth.get_token_url(self._endpoint),
                self._auth.get_password_auth_params(),
            ).json()
        return self._auth_cache

    def build_resource_uri(self, paths, init_uri=None):
        return self._build_resource_uri(paths, init_uri=init_uri)

    def build_collection_uri(self, paths, init_uri=None):
        return self._build_collection_uri(paths, init_uri=init_uri)

    def _insert_auth_header(self, headers):
        result = headers.copy()
        result.update(
            {"Authorization": f"Bearer {self.authenticate()['access_token']}"}
        )
        return result

    def get(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.get(url, headers=headers, **kwargs)

    def post(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.post(url, headers=headers, **kwargs)

    def put(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.put(url, headers=headers, **kwargs)

    def delete(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.delete(url, headers=headers, **kwargs)


class DummyGenesisCoreTestRESTClient(GenesisCoreTestRESTClient):
    def __init__(self, endpoint: str, auth=None, timeout: int = 5):
        auth = auth or GenesisCoreAuth("user", "password")
        self._generate_token()
        super().__init__(endpoint=endpoint, auth=auth, timeout=timeout)

    def _generate_token(self):
        data = {
            "exp": int(datetime.datetime.now().timestamp() + 3600),
            "iat": int(datetime.datetime.now().timestamp()),
            "auth_time": int(datetime.datetime.now().timestamp()),
            "jti": str(uuid.uuid4()),
            "iss": "test_issuer",
            "aud": "test_audience",
            "sub": str(uuid.uuid4()),
            "typ": "test_type",
        }
        self._fake_token = jwt.encode(
            data, os.getenv("HS256_KEY", SECRET), algorithm="HS256"
        )
        return self._fake_token

    def _insert_auth_header(self, headers):
        result = headers.copy()
        result.update({"Authorization": f"Bearer {self._fake_token}"})
        return result
