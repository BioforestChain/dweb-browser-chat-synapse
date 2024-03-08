import logging
from typing import TYPE_CHECKING
from synapse.handlers.register import RegistrationHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

class RegistrationDwebHandler(RegistrationHandler):
    def __init__(self, hs: "HomeServer"):
         super().__init__(hs)
    
    async def is_exist_by_wallet_address(
        self,
        wallet_address: str,
    ) -> bool:
        userInfo = await self.store.get_user_by_wallet_address(wallet_address)
        if userInfo is None:
            return False
        
        return True