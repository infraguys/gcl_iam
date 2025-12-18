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

import abc
import base64
import binascii
import logging
import os
import typing as tp

from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import (
    serialization as crypto_serialization,
)
import jwt

import gcl_iam.constants as c
import gcl_iam.exceptions as exc


LOG = logging.getLogger(__name__)

ALGORITHM_HS256 = c.ALGORITHM_HS256
ALGORITHM_RS256 = c.ALGORITHM_RS256


def _prepare_a256gcm_key(key: tp.Union[str, bytes], key_name: str) -> bytes:
    key_bytes: bytes
    if isinstance(key, bytes):
        key_bytes = key
    else:
        try:
            key_bytes = base64.urlsafe_b64decode(key + "===")
        except (TypeError, binascii.Error):
            key_bytes = key.encode("utf-8")

    if len(key_bytes) != 32:
        raise ValueError(f"{key_name} must be 32 bytes for A256GCM")

    return key_bytes


def encrypt_hs256_jwks_secret(
    secret: str,
    encryption_key: tp.Union[str, bytes],
) -> str:
    key_bytes = _prepare_a256gcm_key(encryption_key, key_name="encryption_key")

    nonce = os.urandom(12)
    ciphertext = aead.AESGCM(key_bytes).encrypt(
        nonce,
        secret.encode("utf-8"),
        None,
    )

    nonce_b64 = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii")
    ciphertext_b64 = (
        base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")
    )
    return f"aesgcm:{nonce_b64}.{ciphertext_b64}"


def decrypt_hs256_jwks_secret(
    secret: str,
    decryption_key: tp.Union[str, bytes],
) -> str:
    key_bytes = _prepare_a256gcm_key(decryption_key, key_name="decryption_key")

    if not secret.startswith("aesgcm:"):
        raise ValueError("Unsupported encrypted HS256 secret format")

    try:
        nonce_b64, ciphertext_b64 = secret[len("aesgcm:") :].split(".", 1)
    except ValueError:
        raise ValueError("Invalid encrypted HS256 secret format")

    nonce = base64.urlsafe_b64decode(nonce_b64 + "===")
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + "===")

    aes = aead.AESGCM(key_bytes)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def _to_base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_pem_to_jwk(public_key_pem: str) -> dict:
    public_key = crypto_serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )
    if not isinstance(public_key, crypto_rsa.RSAPublicKey):
        raise ValueError("Unsupported public key type")

    public_numbers = public_key.public_numbers()
    jwk: tp.Dict[str, tp.Any] = {
        "kty": "RSA",
        "use": "sig",
        "alg": ALGORITHM_RS256,
        "n": _to_base64url_uint(public_numbers.n),
        "e": _to_base64url_uint(public_numbers.e),
    }
    return jwk


def generate_rsa_private_key_pem(
    bitness: int = 2048,
    public_exponent: int = 65537,
) -> str:
    allowed_bitness = {2048, 3072, 4096}
    if bitness not in allowed_bitness:
        raise ValueError(
            "Invalid RSA bitness. Allowed values: 2048, 3072, 4096."
        )

    private_key = crypto_rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=bitness,
    )
    private_key_pem = private_key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption(),
    )
    return private_key_pem.decode("utf-8")


def _load_rsa_private_key(private_key_pem: str) -> crypto_rsa.RSAPrivateKey:
    private_key = crypto_serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, crypto_rsa.RSAPrivateKey):
        raise ValueError("Unsupported private key type")
    return private_key


def generate_rsa_public_key_pem(private_key_pem: str) -> str:
    private_key = _load_rsa_private_key(private_key_pem)

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem.decode("utf-8")


def get_rsa_bitness_from_private_key_pem(private_key_pem: str) -> int:
    private_key = _load_rsa_private_key(private_key_pem)

    return int(private_key.key_size)


class AbstractAlgorithm(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def decode(self, data: str) -> tp.Dict[str, tp.Any]:
        raise NotImplementedError("Not implemented")

    @abc.abstractmethod
    def encode(self, data: tp.Dict[str, tp.Any]) -> str:
        raise NotImplementedError("Not implemented")


class BaseJwtAlgorithm(AbstractAlgorithm):

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        raise NotImplementedError("Not implemented")

    @property
    @abc.abstractmethod
    def candidate_keys(self) -> tp.Iterable[tp.Optional[str]]:
        raise NotImplementedError("Not implemented")

    def _jwt_decode_options(
        self,
        verify: bool,
        ignore_audience: bool,
        ignore_expiration: bool,
    ) -> tp.Dict[str, bool]:
        return {
            "verify_signature": verify,
            "verify_exp": not ignore_expiration,
            "verify_aud": not ignore_audience,
        }

    def _decode_with_fallback_keys(
        self,
        data: str,
        keys: tp.Iterable[tp.Optional[str]],
        algorithm: str,
        options: tp.Dict[str, bool],
        audience: tp.Optional[str],
    ) -> tp.Dict[str, tp.Any]:
        for key in keys:
            if key is None:
                continue
            try:
                return jwt.decode(
                    data,
                    key=key,
                    algorithms=[algorithm],
                    options=options,
                    audience=audience,
                )
            except jwt.exceptions.DecodeError as e:
                LOG.warning("Invalid token by reason: %s", e)
                continue
        raise exc.CredentialsAreInvalidError()

    def decode(
        self,
        data: str,
        audience: tp.Optional[str] = None,
        ignore_audience: bool = False,
        ignore_expiration: bool = False,
        verify: bool = True,
    ) -> tp.Dict[str, tp.Any]:
        options = self._jwt_decode_options(
            verify=verify,
            ignore_audience=ignore_audience,
            ignore_expiration=ignore_expiration,
        )
        return self._decode_with_fallback_keys(
            data,
            keys=self.candidate_keys,
            algorithm=self.algorithm,
            options=options,
            audience=audience,
        )


class HS256(BaseJwtAlgorithm):

    def __init__(self, key: str, previous_key: tp.Optional[str] = None):
        super().__init__()
        self._key = key
        self._previous_key = previous_key

    @property
    def algorithm(self) -> str:
        return ALGORITHM_HS256

    @property
    def candidate_keys(self) -> tp.Iterable[tp.Optional[str]]:
        return (self._key, self._previous_key)

    def encode(self, data: tp.Dict[str, tp.Any]) -> str:
        return jwt.encode(data, key=self._key, algorithm=ALGORITHM_HS256)


class RS256VerifyOnly(BaseJwtAlgorithm):

    def __init__(
        self,
        public_key: str,
        previous_public_key: tp.Optional[str] = None,
    ):
        super().__init__()
        self._public_key = public_key
        self._previous_public_key = previous_public_key

    @property
    def algorithm(self) -> str:
        return ALGORITHM_RS256

    @property
    def candidate_keys(self) -> tp.Iterable[tp.Optional[str]]:
        return (self._public_key, self._previous_public_key)

    def encode(self, data):
        raise NotImplementedError("Signing is not supported by this algorithm")


class RS256(RS256VerifyOnly):

    def __init__(
        self,
        private_key: str,
        public_key: str,
        previous_public_key: tp.Optional[str] = None,
    ):
        super().__init__(
            public_key=public_key,
            previous_public_key=previous_public_key,
        )
        self._private_key = private_key

    def encode(self, data: tp.Dict[str, tp.Any]) -> str:
        return jwt.encode(
            data,
            key=self._private_key,
            algorithm=ALGORITHM_RS256,
        )
