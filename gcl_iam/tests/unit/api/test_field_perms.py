# Copyright 2026 Genesis Corporation.
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

import pytest
from unittest.mock import Mock, patch

from restalchemy.api import constants
from gcl_iam import rules
from gcl_iam.api.field_perms import FieldsIamPermissions, Permissions


def test_init_with_rule_permissions():
    """Test that FieldsIamPermissions accepts rule-based permissions"""
    fields = {
        "field1": {constants.ALL: rules.Rule("service", "resource", "permission")}
    }

    # This should not raise an exception
    permissions = FieldsIamPermissions(fields=fields)

    assert permissions.fields == fields


def test_init_invalid_method():
    """Test that FieldsIamPermissions raises assertion error for invalid methods"""
    fields = {"field1": {"INVALID_METHOD": Permissions.HIDDEN}}

    # This should raise an AssertionError
    with pytest.raises(AssertionError):
        FieldsIamPermissions(fields=fields)


def test_init_invalid_permission():
    """Test that FieldsIamPermissions raises assertion error for invalid permissions"""
    fields = {"field1": {constants.GET: "INVALID_PERMISSION"}}

    # This should raise an AssertionError
    with pytest.raises(AssertionError):
        FieldsIamPermissions(fields=fields)


def test_usual_permissions():
    """Test default permissions without Rules"""
    mock_enforcer = Mock()
    mock_context = Mock()
    mock_context.iam_context.enforcer = mock_enforcer

    fields = {
        "field1": {
            constants.GET: Permissions.HIDDEN,
            constants.CREATE: Permissions.RO,
        }
    }

    mock_req = Mock()
    mock_req.api_context.get_active_method.return_value = constants.CREATE

    with patch("gcl_iam.api.field_perms.contexts.get_context") as mock_get_context:
        mock_get_context.return_value = mock_context
        mock_enforcer.enforce.return_value = True

        permissions = FieldsIamPermissions(fields=fields)

        assert permissions.meets_field_permission("field1", mock_req, Permissions.RW)
        assert permissions.meets_field_permission("field1", mock_req, Permissions.RO)
        assert not permissions.meets_field_permission(
            "field1", mock_req, Permissions.HIDDEN
        )


def test_meets_field_permission_default_permission():
    """Test meets_field_permission with default permission"""
    mock_enforcer = Mock()
    mock_context = Mock()
    mock_context.iam_context.enforcer = mock_enforcer

    fields = {"field1": {constants.CREATE: Permissions.RO}}

    mock_req = Mock()
    mock_req.api_context.get_active_method.return_value = constants.GET

    with patch("gcl_iam.api.field_perms.contexts.get_context") as mock_get_context:
        mock_get_context.return_value = mock_context
        mock_enforcer.enforce.return_value = True

        permissions = FieldsIamPermissions(fields=fields, default=Permissions.HIDDEN)

        # Test with field not in permissions dict - should use default
        result = permissions.meets_field_permission("field2", mock_req, Permissions.RW)
        assert result is True


def test_meets_field_permission_rule_enforcement_positive():
    """Test meets_field_permission with rule enforcement returning positive result"""
    mock_enforcer = Mock()
    mock_context = Mock()
    mock_context.iam_context.enforcer = mock_enforcer

    fields = {
        "field1": {constants.ALL: rules.Rule("service", "resource", "permission")}
    }

    mock_req = Mock()
    mock_req.api_context.get_active_method.return_value = constants.GET

    with patch("gcl_iam.api.field_perms.contexts.get_context") as mock_get_context:
        mock_get_context.return_value = mock_context
        mock_enforcer.enforce.return_value = True

        permissions = FieldsIamPermissions(fields=fields)

        assert permissions.meets_field_permission("field1", mock_req, Permissions.RW)
        assert not permissions.meets_field_permission(
            "field1", mock_req, Permissions.RO
        )
        assert not permissions.meets_field_permission(
            "field1", mock_req, Permissions.HIDDEN
        )


def test_meets_field_permission_rule_enforcement_negative():
    """Test meets_field_permission with rule enforcement returning negative result"""
    mock_enforcer = Mock()
    mock_context = Mock()
    mock_context.iam_context.enforcer = mock_enforcer

    fields = {
        "field1": {constants.ALL: rules.Rule("service", "resource", "permission")}
    }

    mock_req = Mock()
    mock_req.api_context.get_active_method.return_value = constants.GET

    with patch("gcl_iam.api.field_perms.contexts.get_context") as mock_get_context:
        mock_get_context.return_value = mock_context
        mock_enforcer.enforce.return_value = False

        permissions = FieldsIamPermissions(fields=fields)

        assert permissions.meets_field_permission("field1", mock_req, Permissions.RW)
        assert permissions.meets_field_permission("field1", mock_req, Permissions.RO)
        assert permissions.meets_field_permission(
            "field1", mock_req, Permissions.HIDDEN
        )


def test_meets_field_permission_no_permission():
    """Test meets_field_permission when no permissions are set"""
    mock_enforcer = Mock()
    mock_context = Mock()
    mock_context.iam_context.enforcer = mock_enforcer

    fields = {}

    mock_req = Mock()
    mock_req.api_context.get_active_method.return_value = constants.GET

    with patch("gcl_iam.api.field_perms.contexts.get_context") as mock_get_context:
        mock_get_context.return_value = mock_context
        mock_enforcer.enforce.return_value = True

        permissions = FieldsIamPermissions(fields=fields)

        result = permissions.meets_field_permission("field1", mock_req, Permissions.RW)
        assert result is True
