import logging
import random
from typing import TYPE_CHECKING, List, Optional, Tuple

from synapse.api.errors import (
    Codes,
    InteractiveAuthIncompleteError,
    NotApprovedError,
    SynapseError,
    ThreepidValidationError,
    UnrecognizedRequestError,
)
from synapse.config.server import is_threepid_reserved
from synapse.handlers.auth import AuthHandler
from synapse.handlers.ui_auth import UIAuthSessionDataConstants
from synapse.api.constants import (
    APP_SERVICE_REGISTRATION_TYPE,
    ApprovalNoticeMedium,
    LoginType,
)
from ._base import client_patterns, interactive_auth_handler
from synapse.http.server import HttpServer, finish_request, respond_with_html
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.util.hash import md5_string
from synapse.util.libsodium import SignVerify
from synapse.types import JsonDict
from synapse.rest.client.register import RegisterRestServlet

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

'''
dweb注册：
1. 根据公钥验证签名
2. 若新用户则新增
3. 生成access_token并返回
'''
class RegisterDwebRestServlet(RegisterRestServlet):
    PATTERNS = client_patterns("/account/auth$")
    CATEGORY = "Registration/login requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.ratelimiter = hs.get_registration_ratelimiter()
        self._cache = hs.get_external_cache()
        self._cache_name = 'chall'

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_json_object_from_request(request)

        logger.info('dweb auth: ', body)

        client_addr = request.getClientAddress().host

        await self.ratelimiter.ratelimit(None, client_addr, update=False)

        publicKey = body.get('publicKey')
        sign = body.get('sign')
        if publicKey is None or sign is None:
            raise SynapseError(400, "Invalid publicKey or sign")

        key = md5_string(publicKey)
        challenge = await self._cache.get(self._cache_name,  key)
        if challenge is None:
            raise SynapseError(400, "Not found challenge")

        if not SignVerify(challenge, sign, publicKey):
            raise SynapseError(400, "Signature verification failed")
        
        address = body.get('address')
        if address is None:
            raise SynapseError(400, "Invalid address")
        
        # 检查是否新用户
            # 新用户则新增
        # 返回access_token

        # access_token
        # register_device
        return 200, dict(sign=body.get('sign'))
    
    async def _register(self, body: JsonDict):
        # body = parse_json_object_from_request(request)
        body = JsonDict(username='test007', initial_device_display_name='172.30.95.85: Chrome ..on Windows', client_addr='172.30.95.85')

        # client_addr = request.getClientAddress().host
        client_addr = body.get('client_addr')

        # await self.ratelimiter.ratelimit(None, client_addr, update=False)

        # kind = parse_string(request, "kind", default="user")

        # if kind == "guest":
        #     ret = await self._do_guest_registration(body, address=client_addr)
        #     return ret
        # elif kind != "user":
        #     raise UnrecognizedRequestError(
        #         f"Do not understand membership kind: {kind}",
        #     )

        # Check if the clients wishes for this registration to issue a refresh
        # token.
        # client_requested_refresh_tokens = body.get("refresh_token", False)
        # if not isinstance(client_requested_refresh_tokens, bool):
        #     raise SynapseError(400, "`refresh_token` should be true or false.")

        should_issue_refresh_token = False

        # Pull out the provided username and do basic sanity checks early since
        # the auth layer will store these in sessions.
        desired_username = None
        if "username" in body:
            desired_username = body["username"]
            if not isinstance(desired_username, str) or len(desired_username) > 512:
                raise SynapseError(400, "Invalid username")

        # fork off as soon as possible for ASes which have completely
        # different registration flows to normal users

        
        # == Normal User Registration == (everyone else)
        if not self._registration_enabled:
            raise SynapseError(403, "Registration has been disabled", Codes.FORBIDDEN)

        # For regular registration, convert the provided username to lowercase
        # before attempting to register it. This should mean that people who try
        # to register with upper-case in their usernames don't get a nasty surprise.
        #
        # Note that we treat usernames case-insensitively in login, so they are
        # free to carry on imagining that their username is CrAzYh4cKeR if that
        # keeps them happy.
        if desired_username is not None:
            desired_username = desired_username.lower()

        # Check if this account is upgrading from a guest account.
        guest_access_token = body.get("guest_access_token", None)

        # Pull out the provided password and do basic sanity checks early.
        #
        # Note that we remove the password from the body since the auth layer
        # will store the body in the session and we don't want a plaintext
        # password store there.
        password = body.pop("password", None)
        if password is not None:
            if not isinstance(password, str) or len(password) > 512:
                raise SynapseError(400, "Invalid password")
            self.password_policy_handler.validate_password(password)

        if "initial_device_display_name" in body and password is None:
            # ignore 'initial_device_display_name' if sent without
            # a password to work around a client bug where it sent
            # the 'initial_device_display_name' param alone, wiping out
            # the original registration params
            logger.warning("Ignoring initial_device_display_name without password")
            del body["initial_device_display_name"]

        # session_id = self.auth_handler.get_session_id(body)
        session_id = None
        registered_user_id = None
        password_hash = None
        # if session_id:
        #     # if we get a registered user id out of here, it means we previously
        #     # registered a user for this session, so we could just return the
        #     # user here. We carry on and go through the auth checks though,
        #     # for paranoia.
        #     registered_user_id = await self.auth_handler.get_session_data(
        #         session_id, UIAuthSessionDataConstants.REGISTERED_USER_ID, None
        #     )
        #     # Extract the previously-hashed password from the session.
        #     password_hash = await self.auth_handler.get_session_data(
        #         session_id, UIAuthSessionDataConstants.PASSWORD_HASH, None
        #     )

        # Ensure that the username is valid.
        if desired_username is not None:
            await self.registration_handler.check_username(
                desired_username,
                guest_access_token=guest_access_token,
                assigned_user_id=registered_user_id,
                inhibit_user_in_use_error=self._inhibit_user_in_use_error,
            )

        auth_result = dict(LoginType.DUMMY, True)
        params = dict(username='test007', initial_device_display_name='172.30.95.85: Chromexxxx on Windows')
        session_id = None

        # Check if the user-interactive authentication flows are complete, if
        # not this will raise a user-interactive auth error.
        # try:
        #     auth_result, params, session_id = await self.auth_handler.check_ui_auth(
        #         self._registration_flows,
        #         request,
        #         body,
        #         "register a new account",
        #     )
        # except InteractiveAuthIncompleteError as e:
        #     # The user needs to provide more steps to complete auth.
        #     #
        #     # Hash the password and store it with the session since the client
        #     # is not required to provide the password again.
        #     #
        #     # If a password hash was previously stored we will not attempt to
        #     # re-hash and store it for efficiency. This assumes the password
        #     # does not change throughout the authentication flow, but this
        #     # should be fine since the data is meant to be consistent.
        #     if not password_hash and password:
        #         password_hash = await self.auth_handler.hash(password)
        #         await self.auth_handler.set_session_data(
        #             e.session_id,
        #             UIAuthSessionDataConstants.PASSWORD_HASH,
        #             password_hash,
        #         )
        #     raise

        if registered_user_id is not None:
            logger.info(
                "Already registered user ID %r for this session", registered_user_id
            )
            # don't re-register the threepids
            registered = False
        else:
            # If we have a password in this request, prefer it. Otherwise, there
            # might be a password hash from an earlier request.
            if password:
                password_hash = await self.auth_handler.hash(password)
            if not password_hash:
                raise SynapseError(400, "Missing params: password", Codes.MISSING_PARAM)

            desired_username = (
                await (
                    self.password_auth_provider.get_username_for_registration(
                        auth_result,
                        params,
                    )
                )
            )

            if desired_username is None:
                desired_username = params.get("username", None)

            guest_access_token = params.get("guest_access_token", None)

            if desired_username is not None:
                desired_username = desired_username.lower()

            threepid = None
           
                 
            entries = await self.store.get_user_agents_ips_to_ui_auth_session(
                session_id
            )

            display_name = (
                await (
                    self.password_auth_provider.get_displayname_for_registration(
                        auth_result, params
                    )
                )
            )

            registered_user_id = await self.registration_handler.register_user(
                localpart=desired_username,
                password_hash=password_hash,
                guest_access_token=guest_access_token,
                threepid=threepid,
                default_display_name=display_name,
                address=client_addr,
                user_agent_ips=entries,
            )
            # Necessary due to auth checks prior to the threepid being
            # written to the db
            # if threepid:
            #     if is_threepid_reserved(
            #         self.hs.config.server.mau_limits_reserved_threepids, threepid
            #     ):
            #         await self.store.upsert_monthly_active_user(registered_user_id)

            # Remember that the user account has been registered (and the user
            # ID it was registered with, since it might not have been specified).
            # await self.auth_handler.set_session_data(
            #     session_id,
            #     UIAuthSessionDataConstants.REGISTERED_USER_ID,
            #     registered_user_id,
            # )

            registered = True

        return_dict = await self._create_registration_details(
            registered_user_id,
            params,
            should_issue_refresh_token=should_issue_refresh_token,
        )

        if registered:
            # Check if a token was used to authenticate registration
            # registration_token = await self.auth_handler.get_session_data(
            #     session_id,
            #     UIAuthSessionDataConstants.REGISTRATION_TOKEN,
            # )
            # if registration_token:
            #     # Increment the `completed` counter for the token
            #     await self.store.use_registration_token(registration_token)
            #     # Indicate that the token has been successfully used so that
            #     # pending is not decremented again when expiring old UIA sessions.
            #     await self.store.mark_ui_auth_stage_complete(
            #         session_id,
            #         LoginType.REGISTRATION_TOKEN,
            #         True,
            #     )

            await self.registration_handler.post_registration_actions(
                user_id=registered_user_id,
                auth_result=auth_result,
                access_token=return_dict.get("access_token"),
            )

            if self._require_approval:
                raise NotApprovedError(
                    msg="This account needs to be approved by an administrator before it can be used.",
                    approval_notice_medium=ApprovalNoticeMedium.NONE,
                )

        return 200, return_dict

# 生成签名challenge
class RegisterDwebChallenge(RestServlet):
    PATTERNS = client_patterns("/account/challenge$")
    CATEGORY = "Registration/login requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.ratelimiter = hs.get_registration_ratelimiter()
        self._cache = hs.get_external_cache()
        self._cache_name = 'chall'

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_json_object_from_request(request)
    
        client_addr = request.getClientAddress().host
        await self.ratelimiter.ratelimit(None, client_addr, update=False)

        publicKey = body.get('publicKey')
        if publicKey is None:
            raise SynapseError(400, "Invalid publicKey")
        
        key = md5_string(publicKey)
        val = random.randint(100000, 999999)
        await self._cache.set(self._cache_name, key, val, 60*1000)
        
        return 200, dict(challenge=val)
    

def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    RegisterDwebRestServlet(hs).register(http_server)
    RegisterDwebChallenge(hs).register(http_server)