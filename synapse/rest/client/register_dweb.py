import logging
import random
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import (
    Codes,
    NotApprovedError,
    SynapseError,
)
from synapse.api.constants import (
    APP_SERVICE_REGISTRATION_TYPE,
    ApprovalNoticeMedium,
    LoginType,
)
from ._base import client_patterns, interactive_auth_handler
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
)
from synapse.http.server import HttpServer
from synapse.http.site import SynapseRequest
from synapse.util.hash import md5_string
from synapse.util.libsodium import SignVerify
from synapse.util.stringutils import random_string, random_string_with_symbols
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
        self.registration_dweb_handler = hs.get_registration_dweb_handler()
        self._cache = hs.get_external_cache()
        self._cache_name = 'chall'
        self._clock = hs.get_clock()

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
        # for test
        # challenge = "abc"
        if challenge is None:
            raise SynapseError(400, "Not found challenge")

        is_signed = SignVerify(str(challenge), sign, publicKey)
        if not is_signed:
            raise SynapseError(400, "Signature verification failed")
        
        address = body.get('address')
        if address is None:
            raise SynapseError(400, "Invalid address")
        
        # initial_device_display_name='172.30.95.85: Chrome on Windows'
        # TODO 需要前端检测设备
        initial_device_display_name = f'{client_addr}: on Dweb'
        # 检查是否新用户
        userInfo = await self.store.get_user_by_wallet_address(address)
        # is_exist = await self.registration_dweb_handler.is_exist_by_wallet_address(address)
        if userInfo is None:
            # 新用户则新增
            username = random_string(4) + str(self._clock.time_msec())
            password = random_string_with_symbols(12)

            cbody: JsonDict = {'username': username, 'password': password, 'initial_device_display_name': initial_device_display_name, 'client_addr': client_addr}
            logging.info("body %s, %s:", password, cbody)

            try:
                result = await self._register(cbody)
                logging.info('add new user %s: ', result)

                await self.store.add_wallet_address_to_user(result.get('user_id'), address)
            except Exception as err:
                raise err

            result["wallet_address"] = address
            return 200, result

        # 返回access_token
        user_id = userInfo.user_id.to_string()
        (
            device_id,
            access_token,
            valid_until_ms,
            refresh_token,
        ) = await self.registration_handler.register_device(
            user_id,
            device_id=None,
            initial_display_name=initial_device_display_name,
            is_guest=False,
            is_appservice_ghost=False,
            should_issue_refresh_token=False,
        )

        # registered_device_id = await self.device_handler.check_device_registered(
        #     userInfo.get('user_id'),
        #     device_id=None,
        #     initial_device_display_name=initial_device_display_name,
        #     auth_provider_id=None,
        #     auth_provider_session_id=None,
        # )
        # access_token = self.auth_handler.create_access_token_for_user_id(
        #     userInfo.get('user_id'),
        #     device_id=registered_device_id,
        #     valid_until_ms=None,
        #     is_appservice_ghost=False,
        #     refresh_token_id=None,)

        result: JsonDict = {
            "user_id": user_id,
            "wallet_address": address,
            "home_server": self.hs.hostname,
            "access_token": access_token,
            "device_id": device_id,
        }

        return 200, result

    async def _register(self, body: JsonDict) -> JsonDict:
        client_addr = body.get('client_addr')

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

        # Ensure that the username is valid.
        if desired_username is not None:
            await self.registration_handler.check_username(
                desired_username,
                guest_access_token=guest_access_token,
                assigned_user_id=registered_user_id,
                inhibit_user_in_use_error=self._inhibit_user_in_use_error,
            )

        auth_result = {LoginType.DUMMY: True}
        params = dict(username=body.get('username'), initial_device_display_name=body.get('initial_device_display_name'))
        session_id = None

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

            registered = True

        return_dict = await self._create_registration_details(
            registered_user_id,
            params,
            should_issue_refresh_token=should_issue_refresh_token,
        )

        if registered:
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

        return return_dict

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
