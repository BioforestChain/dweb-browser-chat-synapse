
""" This module contains REST servlets to do with profile: /profile/<paths> """

from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_boolean,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.rest.client.profile import ProfileRestServlet
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ProfileDwebRestServlet(ProfileRestServlet):
    PATTERNS = client_patterns("/profile_dweb/(?P<address>[^/]*)", v1=True)
    CATEGORY = "Event sending requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.store = hs.get_datastores().main
        # self.hs = hs
        # self.profile_handler = hs.get_profile_handler()
        # self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, address: str
    ) -> Tuple[int, JsonDict]:
        
        user_info = await self.store.get_user_by_wallet_address(address)
        if user_info is None:
            raise SynapseError(404, "Profile was not found", Codes.NOT_FOUND)

        code, result = await super().on_GET(request, user_info.user_id.to_string())

        print("on_GET: ", code, result)

        return code, result


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ProfileDwebRestServlet(hs).register(http_server)
