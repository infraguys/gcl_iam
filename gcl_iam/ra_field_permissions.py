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

from restalchemy.api import field_permissions


class FieldsLeastGrantPermissions(field_permissions.BasePermissions):
    def __init__(self, fields, default=Permissions.RW):
        """Field permissions container for resource

        This class describes a dict of fields with permissions for
        various RestAlchemy API methods. All permissions are decrared
        in class Permissions. The methods supported by RA are declared
        in the `restalchemy.api.constants` module.
        For example, the code below shows how to set:
        > HIDDEN permissions to the `one_field` for the FILTER method
          and RW for all others RA methods, except FILTER;
        > RO permissions for the `two_field` for all RA methods;
        > HIDDEN permissions for the `three_field` for GET method and
          RO permissions for all others RA methods, except GET.

        ```
        FieldsPermissions(
            default=Permissions.RW,
            fields={
                'one_field':{
                    constants.FILTER: Permissions.HIDDEN},
                'two_field': {
                    constants.ALL: Permissions.RO},
                'three_field': {
                    constants.GET: Permissions.HIDDEN,
                    constants.ALL: Permissions.RO},
            }
        )
        ```

        Pay attention: if you wouldn't set permission for field and RA method
        by default it would be RW (READWRITE) permission.

        :param fields: dict of field model name and permissions
        :param default: default permission for non-described fields
        """
        for method_permission in fields.values():
            for method, permission in method_permission.items():
                assert (
                    method.upper() in constants.ALL_RA_METHODS
                    and permission in Permissions.ALL_PERMISSIONS
                )
        super(FieldsPermissions, self).__init__(permission=default)
        self.fields = fields

    def meets_field_permission(
        self, model_field_name, req, current_permission
    ):

        method = req.api_context.get_active_method()
        field_permission = self.fields.get(model_field_name, {})

        req.iam_context.enforcer.enforce()

        # NOTE(g.melikov): By DEFAULT permission is Permissions.RW
        permission = (
            field_permission.get(method)
            or field_permission.get(constants.ALL)
            or self._permission
        )

        return permission <= current_permission

    def is_readonly(self, model_field_name, req):
        return self.meets_field_permission(
            model_field_name=model_field_name,
            req=req,
            current_permission=Permissions.RO,
        )

    def is_hidden(self, model_field_name, req):
        return self.meets_field_permission(
            model_field_name=model_field_name,
            req=req,
            current_permission=Permissions.HIDDEN,
        )
