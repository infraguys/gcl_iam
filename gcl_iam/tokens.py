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
import typing as tp
import uuid

import jwt


class BaseToken:

    def __init__(
        self,
        token: tp.Optional[str],
        token_info: tp.Optional[dict],
        audience: str,
    ):
        super().__init__()
        self._token = token
        self._token_info = token_info
        self._audience = audience

    @property
    def token(self) -> tp.Optional[str]:
        return self._token

    @property
    def token_info(self) -> tp.Optional[dict]:
        return self._token_info

    @property
    def audience_name(self) -> str:
        return self._audience

    @property
    def uuid(self):
        return uuid.UUID(self._token_info["jti"])


class UnverifiedToken(BaseToken):

    def __init__(self, token: str):
        token_info = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
            },
        )

        super().__init__(
            token=token,
            token_info=token_info,
            audience=token_info["aud"],
        )


class VerifiedToken(BaseToken):

    def __init__(
        self,
        token,
        algorithm,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        token_info = algorithm.decode(
            token,
            audience=None,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )
        audience_name = token_info["aud"]

        super().__init__(
            token=token,
            token_info=token_info,
            audience=audience_name,
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
    def issuer_url(self):
        return self._token_info["iss"]

    @property
    def user_uuid(self):
        return uuid.UUID(self._token_info["sub"])


class AuthToken(VerifiedToken):

    @property
    def autenticated_at(self):
        auth_time = self._token_info["auth_time"]
        return datetime.datetime.fromtimestamp(
            auth_time, tz=datetime.timezone.utc
        )

    @property
    def token_type(self):
        return self._token_info["typ"]

    @property
    def otp_enabled(self):
        return self._token_info.get("otp")


class IdToken(VerifiedToken):

    def __init__(
        self,
        token,
        algorithm,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__(
            token=token,
            algorithm=algorithm,
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


class RefreshToken(VerifiedToken):

    def __init__(
        self,
        token,
        algorithm,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        super().__init__(
            token=token,
            algorithm=algorithm,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
            verify=verify,
        )
