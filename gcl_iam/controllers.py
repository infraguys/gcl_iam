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

import uuid

from restalchemy.api import controllers
from restalchemy.common import contexts
from restalchemy.dm import types

from gcl_iam import enforcers
from gcl_iam import exceptions


class PolicyBasedControllerMixin(object):

    __policy_name__ = None

    def __init__(self, *args, **kwargs):
        self._introspection = (
            contexts.get_context().iam_context.introspection_info()
        )

        # Forbid requests without auth or without project scope
        if not self._introspection:
            raise exceptions.Unauthorized()

        self._ctx_project_id = self._introspection.get("project_id", None)
        self._enforcer = enforcers.Enforcer(self._introspection["permissions"])

        super().__init__(*args, **kwargs)

    def _enforce(self, action):
        if self.__policy_name__:
            policy_key = (
                "genesis_core." + self.__policy_name__ + "." + action
            )  # TODO
        else:
            policy_key = "default"

        return self._enforcer.enforce(policy_key, do_raise=True)

    def _force_project_id(self, project_id):
        # ghosts converts project ids to true UUIDs with dashes
        if not isinstance(project_id, uuid.UUID):
            project_id = uuid.UUID(project_id)
        if project_id != self._ctx_project_id:
            raise exceptions.Forbidden()

    def _enforce_and_authorize_project_id(self, method, project_id):
        if self._enforce(method) and not self._ctx_project_id:
            return

        self._force_project_id(project_id)

    def _enforce_and_override_project_id_in_kwargs(self, method, kwargs):
        if self._enforce(method) and not self._ctx_project_id:
            return

        if "project_id" in kwargs:
            self._force_project_id(kwargs["project_id"])
        else:
            kwargs["project_id"] = types.UUID().from_simple_type(
                self._ctx_project_id
            )


class PolicyBasedController(
    PolicyBasedControllerMixin, controllers.BaseResourceController
):

    def create(self, **kwargs):
        self._enforce_and_override_project_id_in_kwargs("create", kwargs)

        return super(PolicyBasedControllerMixin, self).create(**kwargs)

    def get(self, **kwargs):
        self._enforce_and_override_project_id_in_kwargs("get", kwargs)
        res = super(PolicyBasedControllerMixin, self).get(**kwargs)
        return res

    def filter(self, filters):
        self._enforce_and_override_project_id_in_kwargs("get", filters)
        return super(PolicyBasedController, self).filter(filters)

    def delete(self, uuid):
        filters = {}
        self._enforce_and_override_project_id_in_kwargs("delete", filters)
        dm = super(PolicyBasedController, self).get(uuid, **filters)
        dm.delete()

    def update(self, uuid, **kwargs):
        filters = {}
        self._enforce_and_override_project_id_in_kwargs("update", filters)
        if "project_id" in kwargs and self._ctx_project_id:
            self._force_project_id(kwargs["project_id"])
        dm = super(PolicyBasedController, self).get(uuid, **filters)
        dm.update_dm(values=kwargs)
        dm.update()
        return dm


class NestedPolicyBasedController(
    PolicyBasedControllerMixin, controllers.BaseNestedResourceController
):

    # Nested resources don't have projects, so it will be checked via parent
    def create(self, **kwargs):
        self._enforce("create")
        return super(PolicyBasedControllerMixin, self).create(**kwargs)

    def get(self, **kwargs):
        self._enforce("get")
        return super(PolicyBasedControllerMixin, self).get(**kwargs)

    def filter(self, parent_resource, filters):
        self._enforce("get")
        return super(NestedPolicyBasedController, self).filter(
            parent_resource=parent_resource, filters=filters
        )

    def delete(self, parent_resource, uuid):
        self._enforce("delete")
        super(NestedPolicyBasedController, self).delete(
            parent_resource=parent_resource, uuid=uuid
        )

    def update(self, parent_resource, uuid, **kwargs):
        self._enforce("update")
        return super(NestedPolicyBasedController, self).update(
            parent_resource, uuid, **kwargs
        )


class PolicyBasedWithoutProjectController(PolicyBasedController):

    def get(self, **kwargs):
        self._enforce("get")
        return super(PolicyBasedControllerMixin, self).get(**kwargs)

    def delete(self, uuid):
        self._enforce("delete")
        dm = super(PolicyBasedController, self).get(uuid)
        dm.delete()

    def update(self, uuid, **kwargs):
        self._enforce("update")
        dm = super(PolicyBasedController, self).get(uuid)

        dm.update_dm(values=kwargs)
        dm.update()
        return dm
