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

import pytest
import threading
import uuid

from unittest import mock

from restalchemy.common import contexts

from gcl_iam import controllers
from gcl_iam import engines
from gcl_iam import exceptions


FAKE_PROJECT_ID = uuid.UUID("fbe1fc09-e4cc-4cd2-a51d-c823b40155b2")
FAKE_PROJECT_ID_2 = uuid.UUID("29885802-c8b9-42d5-806f-6ecc1c943bbb")
FAKE_METHOD = "fake_method"


class FakeController(controllers.PolicyBasedControllerMixin):
    __policy_name__ = "vm"

    def __init__(self, *args, **kwargs):
        self._req = mock.Mock()
        super().__init__(*args, **kwargs)


@pytest.fixture
def user_context():
    ctx_storage = mock.Mock()
    contexts.ContextWithStorage._store_context_session(ctx_storage)
    ctx_storage.iam_context.introspection_info.return_value = {
        "user_info": {},
        "project_id": FAKE_PROJECT_ID,
        "otp_verified": True,
        "permission_hash": "xxxx",
        "permissions": [
            "service.resource.action",
            "genesis_core.vm.create",
            "genesis_core.vm.admin",
        ],
    }

    yield ctx_storage.iam_context.introspection_info

    contexts.ContextWithStorage._clear_context()


@pytest.fixture
def unscoped_context():
    ctx_storage = mock.Mock()
    contexts.ContextWithStorage._store_context_session(ctx_storage)
    ctx_storage.iam_context.introspection_info.return_value = {
        "user_info": {},
        "project_id": "",
        "otp_verified": True,
        "permission_hash": "xxxx",
        "permissions": [
            "service.resource.action",
            "genesis_core.vm.create",
            "genesis_core.vm.admin",
            "*.*.*",
        ],
    }

    yield ctx_storage.iam_context.introspection_info

    contexts.ContextWithStorage._clear_context()


class TestPolicyBasedControllerMixin:
    def test_default_init(self, user_context):
        user_context.return_value = {}

        with pytest.raises(exceptions.Unauthorized):
            _ = FakeController()

    def test_default_init_with_ctx_and_project(self, user_context):
        pc = FakeController()

        assert pc._introspection is not None
        assert pc._ctx_project_id == FAKE_PROJECT_ID

    def test_auth_unscoped(self, unscoped_context):
        pc = FakeController()

        assert (
            pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID)
            is None
        )
        assert (
            pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID_2)
            is None
        )

    def test_auth_project_scoped_any_permission(self, unscoped_context):
        unscoped_context.return_value = {
            "user_info": {},
            "project_id": FAKE_PROJECT_ID,
            "otp_verified": True,
            "permission_hash": "xxxx",
            "permissions": [
                "service.resource.action",
                "genesis_core.vm.create",
                "genesis_core.vm.admin",
                "*.*.*",
            ],
        }

        pc = FakeController()

        assert (
            pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID)
            is None
        )

        with pytest.raises(exceptions.Forbidden):
            pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID_2)

    def test_auth_project_id_allowed(self, user_context):
        pc = FakeController()

        pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID)

    def test_auth_project_id_method_forbidden(self, user_context):
        with pytest.raises(exceptions.Forbidden):
            pc = FakeController()
            pc._enforce_and_authorize_project_id(
                "strange_create", FAKE_PROJECT_ID_2
            )

    def test_auth_non_uuid_project_id_allowed(self, user_context):
        pc = FakeController()

        pc._enforce_and_authorize_project_id("create", str(FAKE_PROJECT_ID))

    def test_auth_project_id_not_allowed(self, user_context):
        with pytest.raises(exceptions.Forbidden):
            pc = FakeController()
            pc._enforce_and_authorize_project_id("create", FAKE_PROJECT_ID_2)

    def test_override_project_id_from_filters(self, user_context):
        kwargs = {"project_id": FAKE_PROJECT_ID}
        pc = FakeController()

        pc._enforce_and_override_project_id_in_kwargs("create", kwargs)

        assert kwargs == {"project_id": FAKE_PROJECT_ID}

    def test_override_project_id_from_ctx(self, user_context):
        kwargs = {}
        pc = FakeController()

        pc._enforce_and_override_project_id_in_kwargs("create", kwargs)

        assert kwargs == {"project_id": FAKE_PROJECT_ID}
