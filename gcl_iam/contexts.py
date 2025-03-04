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

from restalchemy.common import contexts

from gcl_iam import constants as c
from gcl_iam import exceptions as e


LOG = logging.getLogger(__name__)


class GenesisCoreAuthContext(contexts.ContextWithStorage):

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
        return self._local_thread_storage.iam_context

    def _store_iam_session(self, iam_contex):
        if hasattr(self._local_thread_storage, c.CONTEXT_STORAGE_KEY):
            raise e.AnotherIamSessionAlreadyStored()

        self._local_thread_storage.iam_context = iam_contex

    def _check_iam_session(self):
        if not hasattr(self._local_thread_storage, "iam_context"):
            raise e.NoIamSessionStored()

    def _remove_iam_session(self):
        self._check_iam_session()
        del self._local_thread_storage.iam_context
