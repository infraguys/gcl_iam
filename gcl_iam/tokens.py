# Copyright 2025 Genesis Corporation
#
# All Rights Reserved.
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
import uuid


class BaseToken:

    def __init__(
        self,
        token,
        algorithm,
        audience=None,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__()
        self._token = token
        self._token_info = algorithm.decode(
            token,
            audience=audience,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )
        self._algorithm = algorithm

    @property
    def expiration_datetime(self):
        exp = self._token_info["exp"]
        return datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)

    @property
    def created_at(self):
        iat = self._token_info["iat"]
        return datetime.datetime.fromtimestamp(iat, tz=datetime.timezone.utc)

    @property
    def uuid(self):
        return uuid.UUID(self._token_info["jti"])

    @property
    def issuer_url(self):
        return self._token_info["iss"]

    @property
    def audience_name(self):
        return self._token_info["aud"]

    @property
    def user_uuid(self):
        return uuid.UUID(self._token_info["sub"])

    @property
    def token(self):
        return self._token


class AuthToken(BaseToken):

    def __init__(
        self,
        token,
        algorithm,
        audience=None,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__(
            token=token,
            algorithm=algorithm,
            audience=audience,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )

    @property
    def autenticated_at(self):
        auth_time = self._token_info["auth_time"]
        return datetime.datetime.fromtimestamp(
            auth_time, tz=datetime.timezone.utc
        )

    @property
    def token_type(self):
        return self._token_info["typ"]


class IdToken(BaseToken):

    def __init__(
        self,
        token,
        algorithm,
        audience=None,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__(
            token=token,
            algorithm=algorithm,
            audience=audience,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )

    @property
    def autenticated_at(self):
        auth_time = self._token_info["auth_time"]
        return datetime.datetime.fromtimestamp(
            auth_time, tz=datetime.timezone.utc
        )

    @property
    def user_name(self):
        return self._token_info["name"]

    @property
    def user_email(self):
        return self._token_info["email"]


class RefreshToken(BaseToken):

    def __init__(
        self,
        token,
        algorithm,
        audience=None,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__(
            token=token,
            algorithm=algorithm,
            audience=audience,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )
