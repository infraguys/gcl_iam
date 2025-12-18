#    Copyright 2011 OpenStack Foundation.
#    Copyright 2020 Eugene Frolov
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
import logging
import re
from http import client as http_client

from restalchemy.api.middlewares import contexts as contexts_mw
from restalchemy.api.middlewares import errors as errors_mw

from gcl_iam import contexts
from gcl_iam import engines
from gcl_iam import exceptions as exc
from gcl_iam import tokens

LOG = logging.getLogger(__name__)


class AbstactEndpointComparator(metaclass=abc.ABCMeta):

    def _build_full_path(self, path):
        return re.compile(path)

    @abc.abstractmethod
    def compare(self, req):
        raise NotImplementedError("Not implemented")


class EndpointComparator(AbstactEndpointComparator):
    def __init__(self, path, methods=None):
        self._path = path
        self._methods = methods or ["GET"]

    def compare(self, req):
        full_path = self._build_full_path(self._path)
        return full_path.fullmatch(req.path) and req.method in self._methods


class GenesisCoreAuthMiddleware(contexts_mw.ContextMiddleware):

    def __init__(
        self,
        application,
        iam_engine_driver,
        context_class=contexts.GenesisCoreAuthContext,
        context_kwargs=None,
        skip_auth_endpoints: list = None,
    ):
        super().__init__(
            application=application,
            context_class=context_class,
            context_kwargs=context_kwargs,
        )
        self._iam_engine_driver = iam_engine_driver
        self._skip_auth_endpoints = skip_auth_endpoints or []

    def _construct_context(self, req):
        return self._context_class(req=req, **self._context_kwargs)

    def _should_skip_auth(self, req):
        for endpoint in self._skip_auth_endpoints:
            if endpoint.compare(req):
                return True
        return False

    def _get_auth_token(self, req):
        header_value = req.headers.get("Authorization", "")
        if header_value.lower().startswith("bearer "):
            return header_value.split(" ")[1]
        raise exc.InvalidAuthTokenError()

    def _get_otp_code(self, req):
        if "X-OTP" not in req.headers:
            return None
        return int(req.headers["X-OTP"])

    def _get_unverified_token_info(
        self, auth_token: str
    ) -> tokens.UnverifiedToken:
        return tokens.UnverifiedToken(auth_token)

    def _get_response(self, ctx, req):
        with ctx.context_manager():
            if self._should_skip_auth(req):
                LOG.info("Skip auth for %s", req.path)
                return super()._get_response(ctx, req)
            else:
                try:
                    auth_token = self._get_auth_token(req)
                    token_info = self._get_unverified_token_info(auth_token)

                    algorithm = self._iam_engine_driver.get_algorithm(
                        token_info
                    )
                    iam_context = engines.IamEngine(
                        auth_token=auth_token,
                        algorithm=algorithm,
                        driver=self._iam_engine_driver,
                        otp_code=self._get_otp_code(req),
                    )
                except exc.OTPInvalidCodeError:
                    raise
                except Exception:
                    LOG.exception("Invalid auth token by reason:")
                    raise exc.InvalidAuthTokenError()

                with ctx.iam_session(iam_context):
                    req.iam_engine = iam_context
                    return super()._get_response(ctx, req)


class ErrorsHandlerMiddleware(errors_mw.ErrorsHandlerMiddleware):

    forbidden_exc = (exc.CommonForbiddenError,)

    def _construct_error_response(self, req, e):
        if isinstance(e, exc.ClientAuthenticationError):
            # RFC 6749
            return req.ResponseClass(
                status=http_client.UNAUTHORIZED,
                json={
                    "error": "invalid_client",
                    "error_description": str(e),
                },
            )
        elif isinstance(e, exc.InvalidAuthTokenError):
            return req.ResponseClass(
                status=http_client.UNAUTHORIZED,
                json={
                    "error": "invalid_token",
                    "error_description": str(e),
                },
            )
        elif isinstance(e, exc.CredentialsAreInvalidError):
            # RFC 6749
            return req.ResponseClass(
                status=http_client.BAD_REQUEST,
                json={
                    "error": "invalid_grant",
                    "error_description": str(e),
                },
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        elif isinstance(e, self.forbidden_exc):
            return req.ResponseClass(
                status=http_client.FORBIDDEN,
                json=errors_mw.exception2dict(e),
            )
        else:
            return super()._construct_error_response(req, e)
