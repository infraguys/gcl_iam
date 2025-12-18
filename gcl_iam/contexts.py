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

import contextlib
import logging
import urllib.parse

from restalchemy.common import contexts
from restalchemy.storage.sql import engines

from gcl_iam import constants as c
from gcl_iam import exceptions as e


LOG = logging.getLogger(__name__)


class GenesisCoreAuthContext(contexts.ContextWithStorage):

    def __init__(
        self,
        req,
        engine_name: str = engines.DEFAULT_NAME,
        context_storage: contexts.Storage = None,
    ):
        super().__init__(engine_name, context_storage)
        self._req = req

    @property
    def request(self):
        return self._req

    def get_real_url_with_prefix(self):
        headers = self._req.headers
        fallback_url = self._req.host_url

        forwarded_proto = headers.get("X-Forwarded-Proto")
        forwarded_host = headers.get("X-Forwarded-Host")
        forwarded_port = headers.get("X-Forwarded-Port")
        forwarded_prefix = headers.get("X-Forwarded-Prefix")

        parsed = urllib.parse.urlsplit(fallback_url)

        scheme = forwarded_proto or parsed.scheme
        host = forwarded_host or parsed.hostname
        port = forwarded_port or parsed.port

        new_uri = (
            f"{scheme}://{host}:{port}"
            if port is not None
            else f"{scheme}://{host}"
        )

        if forwarded_prefix:
            new_uri += forwarded_prefix.rstrip("/")

        return new_uri

    @contextlib.contextmanager
    def iam_session(self, iam_context):
        self._store_iam_session(iam_context)
        try:
            LOG.debug("Start iam session with context: %s", iam_context)
            yield iam_context
        finally:
            LOG.debug("End iam session with context: %s", iam_context)
            self._remove_iam_session()

    @property
    def iam_context(self):
        self._check_iam_session()
        return getattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY)

    def _store_iam_session(self, iam_contex):
        if hasattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY):
            raise e.AnotherIamSessionAlreadyStored()

        setattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY, iam_contex)

    def _check_iam_session(self):
        if not hasattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY):
            raise e.NoIamSessionStored()

    def _remove_iam_session(self):
        self._check_iam_session()
        delattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY)
