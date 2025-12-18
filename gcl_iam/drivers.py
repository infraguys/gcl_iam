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
import base64
import dataclasses
import functools
import time
import typing as tp

import bazooka
import bazooka.exceptions
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives import (
    serialization as crypto_serialization,
)
from restalchemy.common import utils

from gcl_iam import algorithms
from gcl_iam import exceptions
from gcl_iam import tokens


class AbstractAuthDriver(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_introspection_info(self, token_info, otp_code=None):
        raise NotImplementedError("Not implemented")

    @abc.abstractmethod
    def get_algorithm(
        self,
        token_info: tokens.UnverifiedToken,
    ) -> algorithms.AbstractAlgorithm:
        raise NotImplementedError("Not implemented")


@dataclasses.dataclass(frozen=True)
class AlgorithmKeys:
    pass


@dataclasses.dataclass(frozen=True)
class HS256AlgorithmKeys(AlgorithmKeys):
    key: str
    previous_key: tp.Optional[str] = None


@dataclasses.dataclass(frozen=True)
class RS256AlgorithmKeys(AlgorithmKeys):
    public_key: str
    previous_public_key: tp.Optional[str] = None


def _base64url_to_int(value: str) -> int:
    decoded = base64.urlsafe_b64decode(value + "===")
    return int.from_bytes(decoded, byteorder="big")


def _rsa_jwk_to_public_key_pem(jwk: tp.Dict[str, tp.Any]) -> str:
    n = jwk["n"]
    e = jwk["e"]

    public_numbers = crypto_rsa.RSAPublicNumbers(
        e=_base64url_to_int(e),
        n=_base64url_to_int(n),
    )
    public_key = public_numbers.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem.decode("utf-8")


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
        self.algorithm_keys: tp.Dict[str, AlgorithmKeys] = {}

    def get_introspection_info(self, token_info, otp_code=None):
        return {
            "user_info": {
                "uuid": self.user_uuid,
                "name": self.user_name,
                "first_name": self.user_first_name,
                "last_name": self.user_last_name,
                "email": self.user_email,
            },
            "project_id": self.project_id,
            "otp_verified": True if otp_code else self.otp_verified,
            "permission_hash": self.permission_hash,
            "permissions": self.permissions,
        }

    def get_algorithm(
        self,
        token_info: tokens.UnverifiedToken,
    ) -> algorithms.AbstractAlgorithm:
        audience = token_info.audience_name
        if audience not in self.algorithm_keys:
            raise KeyError(f"Unknown audience: {audience}")
        keys = self.algorithm_keys[audience]

        if isinstance(keys, HS256AlgorithmKeys):
            return algorithms.HS256(
                key=keys.key,
                previous_key=keys.previous_key,
            )

        if isinstance(keys, RS256AlgorithmKeys):
            return algorithms.RS256VerifyOnly(
                public_key=keys.public_key,
                previous_public_key=keys.previous_public_key,
            )

        raise TypeError(f"Unexpected algorithm keys type: {type(keys)!r}")


class HttpDriver(AbstractAuthDriver):

    def __init__(
        self,
        iam_endpoint: str,
        hs256_jwks_decryption_key: str,
        default_timeout=5,
        cache_maxsize: int = 100,
        cache_ttl_seconds: int = 300,
    ):
        super().__init__()
        self._iam_endpoint = utils.lastslash(iam_endpoint)
        self._client = bazooka.Client(default_timeout=default_timeout)
        self._cache_ttl_seconds = cache_ttl_seconds
        self._hs256_jwks_decryption_key = hs256_jwks_decryption_key

        self._get_algorithm_cached = functools.lru_cache(
            maxsize=cache_maxsize
        )(
            self._get_algorithm_uncached,
        )

    def get_introspection_info(self, token_info, otp_code=None):
        audience = token_info.audience_name
        introspection_url = (
            f"{self._iam_endpoint}v1/iam/clients/{audience}/actions/introspect"
        )
        headers = {"Authorization": f"Bearer {token_info.token}"}
        if otp_code is not None:
            headers["X-OTP"] = otp_code
        try:
            return self._client.get(
                introspection_url,
                headers=headers,
            ).json()
        except bazooka.exceptions.BadRequestError:
            raise exceptions.InvalidAuthTokenError()

    def get_algorithm(
        self,
        token_info: tokens.UnverifiedToken,
    ) -> algorithms.AbstractAlgorithm:
        audience = token_info.audience_name
        time_bucket = int(time.time() // self._cache_ttl_seconds)
        return self._get_algorithm_cached(audience, time_bucket)

    def _get_algorithm_uncached(
        self,
        audience: str,
        time_bucket: int,
    ) -> algorithms.AbstractAlgorithm:
        jwks_url = (
            f"{self._iam_endpoint}v1/iam/clients/{audience}/actions/jwks"
        )

        payload = self._client.get(
            jwks_url,
        ).json()

        algorithm = payload["algorithm"]
        if algorithm == algorithms.ALGORITHM_HS256:
            hs256_keys = [
                k
                for k in payload["keys"]
                if isinstance(k, dict)
                and k.get("alg") == algorithms.ALGORITHM_HS256
                and k.get("kty") == "oct"
                and k.get("k") is not None
            ]
            if not hs256_keys:
                raise ValueError(
                    "HS256 payload keys list does not contain HS256 oct keys"
                )

            encrypted_key = hs256_keys[0]["k"]
            encrypted_previous_key = None
            if len(hs256_keys) > 1:
                encrypted_previous_key = hs256_keys[1]["k"]

            key = algorithms.decrypt_hs256_jwks_secret(
                secret=encrypted_key,
                decryption_key=self._hs256_jwks_decryption_key,
            )
            previous_key = None
            if encrypted_previous_key is not None:
                previous_key = algorithms.decrypt_hs256_jwks_secret(
                    secret=encrypted_previous_key,
                    decryption_key=self._hs256_jwks_decryption_key,
                )

            return algorithms.HS256(
                key=key,
                previous_key=previous_key,
            )

        elif algorithm == algorithms.ALGORITHM_RS256:
            rs256_keys = [
                k
                for k in payload["keys"]
                if isinstance(k, dict)
                and k.get("alg") == algorithms.ALGORITHM_RS256
                and k.get("kty") == "RSA"
                and k.get("n") is not None
                and k.get("e") is not None
            ]
            if not rs256_keys:
                raise ValueError(
                    "RS256 payload keys list does not contain RS256 RSA keys"
                )

            public_key = _rsa_jwk_to_public_key_pem(rs256_keys[0])
            previous_public_key = None
            if len(rs256_keys) > 1:
                previous_public_key = _rsa_jwk_to_public_key_pem(rs256_keys[1])

            return algorithms.RS256VerifyOnly(
                public_key=public_key,
                previous_public_key=previous_public_key,
            )

        raise ValueError("Unsupported algorithm")
