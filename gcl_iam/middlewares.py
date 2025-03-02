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

from restalchemy.api.middlewares import contexts as contexts_mw

from gcl_iam import contexts
from gcl_iam import engines


class GenesisCoreAuthMiddleware(contexts_mw.ContextMiddleware):

    def __init__(
        self,
        application,
        context_class=contexts.GenesisCoreAuthContext,
        context_kwargs=None,
        skip_auth_endpoints: list = None,
    ):
        super().__init__(
            application=application,
            context_class=context_class,
            context_kwargs=context_kwargs,
        )
        self._skip_auth_endpoints = skip_auth_endpoints

    def _get_response(self, ctx, req):
        with ctx.context_manager():
            return super()._get_response(ctx, req)
