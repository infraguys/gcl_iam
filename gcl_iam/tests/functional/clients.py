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

import datetime
import os
import uuid as sys_uuid

import bazooka
from bazooka import common
import jwt


SECRET = "secret"
DEFAULT_ENDPOINT = "http://localhost:11010/v1/"


class GenesisCoreAuth:

    def __init__(
        self,
        username: str,
        password: str,
        client_uuid: str = "00000000-0000-0000-0000-000000000000",
        client_id: str = "GenesisCoreClientId",
        client_secret: str = "GenesisCoreClientSecret",
        uuid: str = "00000000-0000-0000-0000-000000000000",
        email: str = "admin@genesis.com",
        project_id: str = None,
    ):
        super().__init__()
        self._uuid = uuid
        self._email = email
        self._username = username
        self._password = password
        self._client_uuid = client_uuid
        self._client_id = client_id
        self._client_secret = client_secret
        self._project_id = project_id

    def get_client_url(self, endpoint=DEFAULT_ENDPOINT):
        return (
            f"{common.force_last_slash(endpoint)}iam/clients/"
            f"{self._client_uuid}"
        )

    def get_token_url(self, endpoint=DEFAULT_ENDPOINT):
        return f"{self.get_client_url(endpoint)}/actions/get_token/invoke"

    def get_me_url(self, endpoint=DEFAULT_ENDPOINT):
        return f"{self.get_client_url(endpoint)}/actions/me"

    @property
    def uuid(self):
        return self._uuid

    @property
    def email(self):
        return self._email

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def client_uuid(self):
        return self._client_uuid

    @property
    def client_id(self):
        return self._client_id

    @property
    def client_secret(self):
        return self._client_secret

    @property
    def project_id(self):
        return self._project_id

    def get_password_auth_params(self):
        return {
            "grant_type": "password",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "username": self._username,
            "password": self._password,
            "scope": (
                f"project:{self._project_id}" if self._project_id else ""
            ),
        }

    def get_refresh_token_auth_params(self, refresh_token):
        return {
            "grant_type": "refresh_token",
            "refresh_token": "refresh_token",
        }


class GenesisCoreTestNoAuthRESTClient(common.RESTClientMixIn):

    def __init__(self, endpoint: str, timeout: int = 5):
        super().__init__()
        self._endpoint = endpoint
        self._timeout = timeout
        self._client = bazooka.Client(default_timeout=timeout)

    @property
    def endpoint(self):
        return self._endpoint

    def build_resource_uri(self, paths, init_uri=None):
        return self._build_resource_uri(paths, init_uri=init_uri)

    def build_collection_uri(self, paths, init_uri=None):
        return self._build_collection_uri(paths, init_uri=init_uri)

    def get(self, url, **kwargs):
        return self._client.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self._client.post(url, **kwargs)

    def put(self, url, **kwargs):
        return self._client.put(url, **kwargs)

    def delete(self, url, **kwargs):
        return self._client.delete(url, **kwargs)

    def create_user(self, username, password, **kwargs):
        body = {
            "username": username,
            "password": password,
            "first_name": "FirstName",
            "last_name": "LastName",
            "email": f"{username}@genesis.com",
        }
        body.update(kwargs)
        return self._client.post(
            self.build_collection_uri(["iam/users/"]),
            json=body,
        ).json()

    def list_users(self, **kwargs):
        params = kwargs.copy()
        return self.get(
            self.build_collection_uri(["iam/users/"]),
            params=params,
        ).json()

    def update_user(self, uuid, **kwargs):
        return self.put(
            self.build_resource_uri(["iam/users/", uuid]),
            json=kwargs,
        ).json()

    def get_user(self, uuid):
        return self.get(
            self.build_resource_uri(["iam/users/", uuid]),
        ).json()

    def change_user_password(self, uuid, old_password, new_password):
        return self.post(
            self.build_resource_uri(
                ["iam/users/", uuid, "actions/change_password/invoke"],
            ),
            json={
                "old_password": old_password,
                "new_password": new_password,
            },
        ).json()

    def delete_user(self, uuid):
        result = self.delete(
            self.build_resource_uri(["iam/users/", uuid]),
        )
        return None if result.status_code == 204 else result.json()

    def get_user_roles(self, user_uuid):
        return self.get(
            self.build_resource_uri(
                ["iam/users/", user_uuid, "actions/get_my_roles"]
            ),
        ).json()

    def create_role(self, name, description="Functional test role", **kwargs):
        body = kwargs.copy()
        body.update(
            {
                "name": name,
                "description": description,
            }
        )
        return self.post(
            f"{self._endpoint}iam/roles/",
            json=body,
        ).json()

    def create_or_get_role(self, name):
        url = self.build_collection_uri(["iam/roles/"])
        for role in self.get(url=url, params={"name": name}).json():
            return role
        return self.create_role(name=name)

    def create_permission(self, name):
        return self.post(
            f"{self._endpoint}iam/permissions/",
            json={"name": name, "description": "Functional test permission"},
        ).json()

    def create_or_get_permission(self, name):
        url = self.build_collection_uri(["iam/permissions/"])
        for perm in self.get(url=url, params={"name": name}).json():
            return perm
        return self.create_permission(name=name)

    def bind_permission_to_role(self, permission_uuid, role_uuid, **kwargs):
        permission_uri = f"/v1/iam/permissions/{permission_uuid}"
        role_uri = f"/v1/iam/roles/{role_uuid}"
        body = {"permission": permission_uri, "role": role_uri}
        body.update(kwargs)

        return self.post(
            f"{self._endpoint}iam/permission_bindings/",
            json=body,
        ).json()

    def create_or_get_permission_binding(
        self, permission_uuid, role_uuid, **kwargs
    ):
        url = self.build_collection_uri(["iam/permission_bindings/"])
        params = {"permission": permission_uuid, "role": role_uuid}
        params.update(kwargs)
        for bind in self.get(url=url, params=params).json():
            return bind
        return self.bind_permission_to_role(
            permission_uuid, role_uuid, **kwargs
        )

    # TODO(efrolov): delete after refactoring dependencies
    create_or_get_binding = create_or_get_permission_binding

    def bind_role_to_user(self, role_uuid, user_uuid, project_id=None):

        body = {
            "role": f"/v1/iam/roles/{role_uuid}",
            "user": f"/v1/iam/users/{user_uuid}",
        }

        if project_id is not None:
            body["project"] = f"/v1/iam/projects/{project_id}"

        return self.post(
            f"{self._endpoint}iam/role_bindings/",
            json=body,
        ).json()

    def create_or_get_role_binding(
        self, role_uuid, user_uuid, project_id=None
    ):
        url = self.build_collection_uri(["iam/role_bindings/"])
        params = {"role": role_uuid, "user": user_uuid}
        if project_id is not None:
            params["project_id"] = project_id
        for bind in self.get(url=url, params=params).json():
            return bind
        return self.bind_role_to_user(role_uuid, user_uuid, project_id)

    def create_organization(self, name, **kwargs):
        body = kwargs.copy()
        body["name"] = name
        return self.post(
            self.build_collection_uri(["iam/organizations/"]),
            json=body,
        ).json()

    def create_or_get_organization(self, uuid, **kwargs):
        url = self.build_collection_uri(["iam/organizations/"])
        for org in self.get(url=url, params={"uuid": uuid}).json():
            return org
        return self.create_organization(uuid=uuid, **kwargs)

    def list_organizations(self, **kwargs):
        params = kwargs.copy()
        return self.get(
            self.build_collection_uri(["iam/organizations/"]),
            params=params,
        ).json()

    def get_organization(self, uuid):
        return self.get(
            self.build_resource_uri(["iam/organizations/", uuid]),
        ).json()

    def update_organization(self, uuid, **kwargs):
        return self.put(
            self.build_resource_uri(["iam/organizations/", uuid]),
            json=kwargs,
        ).json()

    def delete_organization(self, uuid):
        result = self.delete(
            self.build_resource_uri(["iam/organizations/", uuid]),
        )
        return None if result.status_code == 204 else result.json()

    def create_project(self, organization_uuid, name, **kwargs):
        body = kwargs.copy()
        body["organization"] = f"/v1/iam/organizations/{organization_uuid}"
        body["name"] = name
        return self.post(
            self.build_collection_uri(["iam/projects/"]),
            json=body,
        ).json()

    def create_or_get_project(self, organization_uuid, name, **kwargs):
        url = self.build_collection_uri(["iam/projects/"])
        params = {"organization": organization_uuid, "name": name}
        for proj in self.get(url=url, params=params).json():
            return proj
        return self.create_project(
            organization_uuid=organization_uuid, name=name, **kwargs
        )

    def create_organization_member(
        self, organization_uuid, user_uuid, role, **kwargs
    ):
        body = dict(
            organization=f"/v1/iam/organizations/{organization_uuid}",
            user=f"/v1/iam/users/{user_uuid}",
            role=role,
            **kwargs,
        )
        return self.post(
            self.build_collection_uri(["iam/organization_members/"]),
            json=body,
        ).json()

    def get_organization_members(self, uuid, **kwargs):
        params = kwargs.copy()
        params["organization"] = uuid
        return self.get(
            self.build_collection_uri(["iam/organization_members/"]),
            params=params,
        ).json()

    def set_permissions_to_user(
        self,
        user_uuid: str,
        permissions: list[str] = None,
        project_id: str = None,
    ):
        permissions = permissions or []

        role = self.create_or_get_role(name=f"TestRole[{sys_uuid.uuid4()}]")

        for permission_name in permissions:
            permission = self.create_or_get_permission(
                name=str(permission_name),
            )
            self.create_or_get_permission_binding(
                permission_uuid=permission["uuid"],
                role_uuid=role["uuid"],
            )

        self.create_or_get_role_binding(
            role_uuid=role["uuid"],
            user_uuid=user_uuid,
            project_id=project_id,
        )


class GenesisCoreTestRESTClient(GenesisCoreTestNoAuthRESTClient):

    def __init__(self, endpoint: str, auth: GenesisCoreAuth, timeout: int = 5):
        super().__init__(
            endpoint=endpoint,
            timeout=timeout,
        )
        self._auth = auth
        self._auth_cache = self.authenticate()

    def me(self):
        return self.get(self._auth.get_me_url(self._endpoint)).json()

    def authenticate(self):
        value = getattr(self, "_auth_cache", None)
        if value is None:
            self._auth_cache = self._client.post(
                self._auth.get_token_url(self._endpoint),
                self._auth.get_password_auth_params(),
            ).json()
        return self._auth_cache

    def _insert_auth_header(self, headers):
        result = headers.copy()
        result.update(
            {"Authorization": f"Bearer {self.authenticate()['access_token']}"}
        )
        return result

    def get(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.get(url, headers=headers, **kwargs)

    def post(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.post(url, headers=headers, **kwargs)

    def put(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.put(url, headers=headers, **kwargs)

    def delete(self, url, **kwargs):
        headers = self._insert_auth_header(kwargs.pop("headers", {}))
        return self._client.delete(url, headers=headers, **kwargs)


class DummyGenesisCoreTestRESTClient(GenesisCoreTestRESTClient):
    def __init__(self, endpoint: str, auth=None, timeout: int = 5):
        auth = auth or GenesisCoreAuth("user", "password")
        super().__init__(endpoint=endpoint, auth=auth, timeout=timeout)

    def _generate_token(self):
        data = {
            "exp": int(datetime.datetime.now().timestamp() + 360000),
            "iat": int(datetime.datetime.now().timestamp()),
            "auth_time": int(datetime.datetime.now().timestamp()),
            "jti": str(sys_uuid.uuid4()),
            "iss": "test_issuer",
            "aud": "test_audience",
            "sub": str(sys_uuid.uuid4()),
            "typ": "test_type",
        }
        return jwt.encode(
            data, os.getenv("HS256_KEY", SECRET), algorithm="HS256"
        )

    def authenticate(self):
        value = getattr(self, "_auth_cache", None)
        if value is None:
            self._auth_cache = {"access_token": self._generate_token()}
        return self._auth_cache
