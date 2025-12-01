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

from restalchemy.api import constants
from restalchemy.api import controllers
from restalchemy.common import contexts
from restalchemy.dm import filters
from restalchemy.dm import types

from gcl_iam import exceptions
from gcl_iam import rules


class PolicyBasedControllerMixin(object):

    __policy_service_name__ = ""
    __policy_name__ = None
    _otp_mandatory = set()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._introspection = (
            contexts.get_context().iam_context.introspection_info()
        )

        self._ctx_project_id = self._introspection.get("project_id", None)
        if isinstance(self._ctx_project_id, str):
            self._ctx_project_id = uuid.UUID(self._ctx_project_id)
        self._enforcer = contexts.get_context().iam_context.enforcer

    def _enforce(self, action):
        return self._enforcer.enforce(
            rules.Rule(
                self.__policy_service_name__,
                self.__policy_name__ or "default",
                action,
            ),
            do_raise=True,
        )

    def _force_project_id(self, project_id):
        if isinstance(project_id, filters.AbstractClause):
            project_id = project_id.value
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

    def _check_otp(self, method):
        if (
            self._introspection.get("otp_enabled")
            or method in self._otp_mandatory
        ):
            if not self._introspection.get("otp_verified"):
                raise exceptions.OTPInvalidCodeError()


class PolicyBasedController(
    PolicyBasedControllerMixin, controllers.BaseResourceController
):

    def create(self, **kwargs):
        self._enforce_and_override_project_id_in_kwargs("create", kwargs)

        return super(PolicyBasedControllerMixin, self).create(**kwargs)

    def get(self, **kwargs):
        self._enforce_and_override_project_id_in_kwargs("read", kwargs)
        res = super(PolicyBasedControllerMixin, self).get(**kwargs)
        return res

    def filter(self, filters, order_by=None):
        self._enforce_and_override_project_id_in_kwargs("read", filters)
        return super(PolicyBasedController, self).filter(
            filters, order_by=order_by
        )

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

    # Nested resources may not have projects, so it will be checked via parent
    def create(self, parent_resource, **kwargs):
        if "project_id" in self.model.properties:
            kwargs.setdefault("project_id", parent_resource.project_id)
            self._enforce_and_override_project_id_in_kwargs("create", kwargs)
        else:
            self._enforce("create")
        return super(PolicyBasedControllerMixin, self).create(
            parent_resource=parent_resource, **kwargs
        )

    def get(self, **kwargs):
        self._enforce("read")
        return super(PolicyBasedControllerMixin, self).get(**kwargs)

    def filter(self, parent_resource, filters, order_by=None):
        self._enforce("read")
        return super(NestedPolicyBasedController, self).filter(
            parent_resource=parent_resource, filters=filters, order_by=order_by
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


class PolicyBasedWithoutProjectController(
    PolicyBasedControllerMixin, controllers.BaseResourceController
):

    def create(self, **kwargs):
        self._enforce("create")
        return super().create(**kwargs)

    def get(self, **kwargs):
        self._enforce("read")
        return super().get(**kwargs)

    def filter(self, filters, order_by=None):
        self._enforce("read")
        return super().filter(filters=filters, order_by=order_by)

    def delete(self, uuid):
        self._enforce("delete")
        dm = super().get(uuid)
        dm.delete()

    def update(self, uuid, **kwargs):
        self._enforce("update")
        dm = super().get(uuid)

        dm.update_dm(values=kwargs)
        dm.update()
        return dm


class PolicyBasedCheckOtpController(PolicyBasedController):
    _otp_mandatory = {constants.CREATE, constants.UPDATE, constants.DELETE}

    def create(self, **kwargs):
        self._check_otp(constants.CREATE)
        return super().create(**kwargs)

    def get(self, **kwargs):
        self._check_otp(constants.GET)
        return super().get(**kwargs)

    def filter(self, filters, order_by=None):
        self._check_otp(constants.FILTER)
        return super().filter(filters, order_by=order_by)

    def delete(self, uuid):
        self._check_otp(constants.DELETE)
        super().delete(uuid)

    def update(self, uuid, **kwargs):
        self._check_otp(constants.UPDATE)
        return super().update(uuid, **kwargs)
