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


CONF = cfg.CONF


DOMAIN_IAM = "iam"


def register_iam_cli_opts(conf):

    conf = cfg.CONF

    iam_cli_opts = [
        cfg.StrOpt(
            "iam_endpoint",
            default="http://core.local.genesis-core.tech:11010/",
            help="IAM endpoint used by services",
        ),
        cfg.StrOpt(
            "hs256_jwks_decryption_key",
            default="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            secret=True,
            help="HS256 JWKS decryption key (A256GCM key, base64 or utf-8)",
        ),
    ]

    conf.register_cli_opts(iam_cli_opts, DOMAIN_IAM)
