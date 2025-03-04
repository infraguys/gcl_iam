# Copyright 2025 Genesis Corporation
#
# All Rights Reserved.
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

import jwt

from gcl_iam import constants as c


class AbstractAlgorithm(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def decode(self, data):
        raise NotImplementedError("Not implemented")

    @abc.abstractmethod
    def encode(self, data):
        raise NotImplementedError("Not implemented")


class HS256(AbstractAlgorithm):

    def __init__(self, key):
        super().__init__()
        self._key = key

    def decode(
        self,
        data,
        audience=None,
        ignore_audience=False,
        ignore_expiration=False,
        verify=True,
    ):
        options = {
            "verify_exp": not ignore_expiration,
            "verify_aud": not ignore_audience,
        }
        return jwt.decode(
            data,
            key=self._key,
            algorithms=c.ALGORITHM_HS256,
            options=options,
            audience=audience,
            verify=verify,
        )

    def encode(self, data):
        return jwt.encode(data, key=self._key, algorithm=c.ALGORITHM_HS256)
