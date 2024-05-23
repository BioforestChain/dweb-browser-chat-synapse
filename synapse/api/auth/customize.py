#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2023 The Matrix.org Foundation.
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
from typing import TYPE_CHECKING

import pymacaroons

from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
)
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import active_span, force_tracing, start_active_span
from synapse.types import Requester, create_requester
from synapse.util.cancellation import cancellable

from . import GUEST_DEVICE_ID
from .base import BaseAuth

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class CustomizeAuth(BaseAuth):
    """
    This class contains functions for authenticating users of our client-server API.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        # self.clock = hs.get_clock()
        # self._account_validity_handler = hs.get_account_validity_handler()
        # self._macaroon_generator = hs.get_macaroon_generator()
        #
        # self._force_tracing_for_users = hs.config.tracing.force_tracing_for_users


    @cancellable
    async def verify_auth(
        self,
        # request: SynapseRequest,
        # allow_guest: bool,
        # allow_expired: bool,
        # allow_locked: bool,
    ) -> bool:
        """Helper for get_user_by_req

        Once get_user_by_req has set up the opentracing span, this does the actual work.
        """
        # if b"dWeb_user_directory" in request.uri:
        #
        #    print("dWeb_user_directory route")
        # else:
        try:

            return True
        except KeyError:
            return False
            # raise MissingClientTokenError()




