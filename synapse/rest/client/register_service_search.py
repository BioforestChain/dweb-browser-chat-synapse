#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2017 Vector Creations Ltd
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#

import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import SynapseError, MissingClientTokenError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonMapping


from ._base import client_patterns
from ...util.cancellation import cancellable

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


import base64

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@cancellable
async def verify_auth(
    self,
    decrypted_data_str,
    search_term
) -> bool:
    # TODO: 初步 判断加密的数据 是否 等于 搜索的值
    try:
        if decrypted_data_str ==  search_term:
            return True
    except Exception:
            return False

# 读取私钥文件
def read_private_key(filename):
    try:
        private_key = RSA.import_key(filename)
        return private_key
    except Exception:
        return None

# 使用私钥解密数据
def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_data = cipher.decrypt(ciphertext, None)
    return decrypted_data


class DWebUserDirectorySearchRestServlet(RestServlet):
    PATTERNS = client_patterns("/dWeb_user_directory/search$")
    CATEGORY = "dWeb User directory search requests"

    def __init__(self, hs: "HomeServer"):
        # super().__init__()
        self.hs = hs
        # self.auth = hs.get_auth()
        self.auth = hs.get_customize_auth()
        self.dweb_user_directory_handler = hs.get_dweb_user_directory_handler()



    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonMapping]:
        """Searches for users in directory

        Returns:
            dict of the form::

                {
                    "limited": <bool>,  # whether there were more results or not
                    "results": [  # Ordered by best match first
                        {
                            "user_id": <user_id>,
                            "display_name": <display_name>,
                            "avatar_url": <avatar_url>
                        }
                    ]
                }
        """
        # requester = await self.auth.get_user_by_req(request, allow_guest=True)
        # user_id = requester.user.to_string()

        if not self.hs.config.userdirectory.user_directory_search_enabled:
            return 200, {"limited": False, "results": []}

        body = parse_json_object_from_request(request)
        try:
            # 读取密文数据
            encrypted_data_base64 = body["encrypted_data"]
            b64decode_data = base64.b64decode(encrypted_data_base64)
            # 读取私钥
            private_key = read_private_key(self.hs.get_media_repository().private_key)
            # 使用私钥解密数据
            decrypted_data = rsa_decrypt(b64decode_data, private_key)
            decrypted_data_str = decrypted_data.decode('utf-8')
        except Exception:
            raise SynapseError(400, "`encrypted_data` is required field")


        limit = int(body.get("limit", 10))
        limit = max(min(limit, 50), 0)

        try:
            search_term = body["search_term"]
            res_verify_auth = await verify_auth(self,decrypted_data_str,search_term)
            user_id = "root"
            if res_verify_auth is not True:
                raise SynapseError(400, "`verify_auth` is failed")
        except Exception:
            raise SynapseError(400, "`search_term` is required field")

        results = await self.dweb_user_directory_handler.search_users(
            user_id, search_term, limit
        )
        if results is None:
            raise SynapseError(400, "`wallet_address` is incomplete")
        return 200, results


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    DWebUserDirectorySearchRestServlet(hs).register(http_server)
