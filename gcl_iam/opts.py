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


from oslo_config import cfg

from gcl_iam import algorithms
from gcl_iam import constants as glc_iam_c


CONF = cfg.CONF


DOMAIN_IAM = "iam"
DOMAIN_HS256 = "token_hs256"


def register_iam_cli_opts(conf):

    conf = cfg.CONF

    iam_cli_opts = [
        cfg.StrOpt(
            "token_encryption_algorithm",
            default="HS256",
            choices=("HS256",),
            help="Token encryption algorithm",
        ),
    ]

    iam_cli_token_encryption_algorithms = [
        cfg.StrOpt(
            "encryption_key",
            default="secret",
            help="Token encryption key",
        ),
    ]

    conf.register_cli_opts(iam_cli_opts, DOMAIN_IAM)
    conf.register_cli_opts(iam_cli_token_encryption_algorithms, DOMAIN_HS256)


def get_token_encryption_algorithm(conf=CONF):
    tea_name = conf[DOMAIN_IAM].token_encryption_algorithm
    if tea_name == glc_iam_c.ALGORITHM_HS256:
        return algorithms.HS256(
            key=conf[DOMAIN_HS256].encryption_key,
        )
    else:
        raise ValueError("Unknown token encryption algorithm: {tea_name}")
