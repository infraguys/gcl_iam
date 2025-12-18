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

import base64
import os
import unittest.mock as mock

import jwt
import pytest

import gcl_iam.algorithms as algorithms
import gcl_iam.constants as constants
import gcl_iam.drivers as drivers
import gcl_iam.exceptions as exceptions
import gcl_iam.tokens as tokens


def test_rsa_helpers_roundtrip() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    assert isinstance(private_key_pem, str)

    bitness = algorithms.get_rsa_bitness_from_private_key_pem(private_key_pem)
    assert bitness == 2048

    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)
    assert isinstance(public_key_pem, str)

    jwk = algorithms.public_pem_to_jwk(public_key_pem)
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert isinstance(jwk["n"], str)
    assert isinstance(jwk["e"], str)
    assert "=" not in jwk["n"]
    assert "=" not in jwk["e"]


def test_generate_rsa_private_key_pem_invalid_bitness() -> None:
    with pytest.raises(ValueError):
        algorithms.generate_rsa_private_key_pem(bitness=1024)


def test_hs256_jwks_secret_encrypt_decrypt_roundtrip() -> None:
    key_bytes = os.urandom(32)
    key = base64.urlsafe_b64encode(key_bytes).decode("utf-8").rstrip("=")
    encrypted = algorithms.encrypt_hs256_jwks_secret(
        secret="secret",
        encryption_key=key,
    )
    decrypted = algorithms.decrypt_hs256_jwks_secret(
        secret=encrypted,
        decryption_key=key,
    )
    assert decrypted == "secret"


def test_hs256_jwks_secret_encrypt_decrypt_roundtrip_bytes_key() -> None:
    key_bytes = os.urandom(32)
    encrypted = algorithms.encrypt_hs256_jwks_secret(
        secret="secret",
        encryption_key=key_bytes,
    )
    decrypted = algorithms.decrypt_hs256_jwks_secret(
        secret=encrypted,
        decryption_key=key_bytes,
    )
    assert decrypted == "secret"


def test_hs256_encode_decode_current_key() -> None:
    algo = algorithms.HS256(key="current", previous_key="previous")
    payload = {"sub": "user"}

    token = algo.encode(payload)
    decoded = algo.decode(token)

    assert decoded["sub"] == "user"


def test_hs256_decode_previous_key() -> None:
    algo = algorithms.HS256(key="current", previous_key="previous")
    payload = {"sub": "user"}

    token = jwt.encode(
        payload, key="previous", algorithm=constants.ALGORITHM_HS256
    )
    decoded = algo.decode(token)

    assert decoded["sub"] == "user"


def test_hs256_invalid_token_raises_credentials_invalid() -> None:
    algo = algorithms.HS256(key="current")

    with pytest.raises(exceptions.CredentialsAreInvalidError):
        algo.decode("not-a-jwt")


def test_rs256_encode_decode_current_key() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)

    algo = algorithms.RS256(
        private_key=private_key_pem, public_key=public_key_pem
    )
    payload = {"sub": "user"}

    token = algo.encode(payload)
    decoded = algo.decode(token)

    assert decoded["sub"] == "user"


def test_rs256_decode_previous_public_key() -> None:
    old_private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    old_public_key_pem = algorithms.generate_rsa_public_key_pem(
        old_private_key_pem
    )

    new_private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    new_public_key_pem = algorithms.generate_rsa_public_key_pem(
        new_private_key_pem
    )

    token = jwt.encode(
        {"sub": "user"}, key=old_private_key_pem, algorithm="RS256"
    )

    algo = algorithms.RS256(
        private_key=new_private_key_pem,
        public_key=new_public_key_pem,
        previous_public_key=old_public_key_pem,
    )
    decoded = algo.decode(token)

    assert decoded["sub"] == "user"


def test_rs256_invalid_token_raises_credentials_invalid() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)

    algo = algorithms.RS256(
        private_key=private_key_pem, public_key=public_key_pem
    )

    with pytest.raises(exceptions.CredentialsAreInvalidError):
        algo.decode("not-a-jwt")


def test_rs256_decode_calls_jwt_decode() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)

    algo = algorithms.RS256(
        private_key=private_key_pem, public_key=public_key_pem
    )

    with mock.patch.object(jwt, "decode", wraps=jwt.decode) as jwt_decode:
        token = algo.encode({"sub": "user"})
        algo.decode(token)

    assert jwt_decode.called


def test_rs256_verify_only_decode_ok() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)

    token = jwt.encode({"sub": "user"}, key=private_key_pem, algorithm="RS256")
    algo = algorithms.RS256VerifyOnly(public_key=public_key_pem)

    decoded = algo.decode(token)

    assert decoded["sub"] == "user"


def test_rs256_verify_only_encode_raises() -> None:
    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)

    algo = algorithms.RS256VerifyOnly(public_key=public_key_pem)

    with pytest.raises(NotImplementedError):
        algo.encode({"sub": "user"})


def test_http_driver_get_algorithm_keys_hs256_jwks_payload_ok() -> None:
    aes_key = os.urandom(32)
    aes_key_b64 = base64.urlsafe_b64encode(aes_key).decode("utf-8").rstrip("=")
    encrypted_secret = algorithms.encrypt_hs256_jwks_secret(
        secret="secret",
        encryption_key=aes_key_b64,
    )

    driver = drivers.HttpDriver(
        "http://iam.example/",
        hs256_jwks_decryption_key=aes_key_b64,
    )
    driver._client = mock.Mock()
    driver._client.get.return_value.json.return_value = {
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "use": "sig",
                "kid": "00000000-0000-0000-0000-000000000001",
                "k": encrypted_secret,
            },
        ],
        "algorithm": algorithms.ALGORITHM_HS256,
    }

    token_info = mock.Mock(spec=tokens.UnverifiedToken)
    token_info.audience_name = "client-1"

    algo = driver.get_algorithm(token_info)
    assert isinstance(algo, algorithms.HS256)

    token = algo.encode({"sub": "user"})
    decoded = algo.decode(token)
    assert decoded["sub"] == "user"


def test_http_driver_get_algorithm_rs256_verify_only_jwks_payload_ok() -> None:
    aes_key = os.urandom(32)
    aes_key_b64 = base64.urlsafe_b64encode(aes_key).decode("utf-8").rstrip("=")

    private_key_pem = algorithms.generate_rsa_private_key_pem(bitness=2048)
    public_key_pem = algorithms.generate_rsa_public_key_pem(private_key_pem)
    jwk = algorithms.public_pem_to_jwk(public_key_pem)

    driver = drivers.HttpDriver(
        "http://iam.example/",
        hs256_jwks_decryption_key=aes_key_b64,
    )
    driver._client = mock.Mock()
    driver._client.get.return_value.json.return_value = {
        "algorithm": algorithms.ALGORITHM_RS256,
        "keys": [jwk],
    }

    token_info = mock.Mock(spec=tokens.UnverifiedToken)
    token_info.audience_name = "client-1"

    algo = driver.get_algorithm(token_info)
    assert isinstance(algo, algorithms.RS256VerifyOnly)

    token = jwt.encode({"sub": "user"}, key=private_key_pem, algorithm="RS256")
    decoded = algo.decode(token)
    assert decoded["sub"] == "user"
