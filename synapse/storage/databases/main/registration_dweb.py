import logging
from typing import TYPE_CHECKING, Optional

from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)

from synapse.storage.databases.main.registration import RegistrationWorkerStore, RegistrationStore
from synapse.types import UserID, UserInfo
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

THIRTY_MINUTES_IN_MS = 30 * 60 * 1000

logger = logging.getLogger(__name__)


class RegistrationDwebWorkerStore(RegistrationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

    @cached()
    async def get_user_by_wallet_address(self, wallet_address: str) -> Optional[UserInfo]:
        """Returns info about the user account, if it exists."""

        def get_user_by_wallet_address_txn(txn: LoggingTransaction) -> Optional[UserInfo]:
            # We could technically use simple_select_one here, but it would not perform
            # the COALESCEs (unless hacked into the column names), which could yield
            # confusing results.
            txn.execute(
                """
                SELECT
                    name, wallet_address, is_guest, admin, consent_version, consent_ts,
                    consent_server_notice_sent, appservice_id, creation_ts, user_type,
                    deactivated, COALESCE(shadow_banned, FALSE) AS shadow_banned,
                    COALESCE(approved, TRUE) AS approved,
                    COALESCE(locked, FALSE) AS locked
                FROM users
                WHERE wallet_address = ?
                """,
                (wallet_address,),
            )

            row = txn.fetchone()
            if not row:
                return None

            (
                name,
                waddress,
                is_guest,
                admin,
                consent_version,
                consent_ts,
                consent_server_notice_sent,
                appservice_id,
                creation_ts,
                user_type,
                deactivated,
                shadow_banned,
                approved,
                locked,
            ) = row

            return UserInfo(
                wallet_address=waddress,
                appservice_id=appservice_id,
                consent_server_notice_sent=consent_server_notice_sent,
                consent_version=consent_version,
                consent_ts=consent_ts,
                creation_ts=creation_ts,
                is_admin=bool(admin),
                is_deactivated=bool(deactivated),
                is_guest=bool(is_guest),
                is_shadow_banned=bool(shadow_banned),
                user_id=UserID.from_string(name),
                user_type=user_type,
                approved=bool(approved),
                locked=bool(locked),
            )

        return await self.db_pool.runInteraction(
            desc="get_user_by_wallet_address",
            func=get_user_by_wallet_address_txn,
        )


class RegistrationDwebBackgroundUpdateStore(RegistrationDwebWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # wallet_address实际是unique的，这里设置False是为了最小改动实现wallet_address逻辑
        # 所以wallet_address的唯一性需要代码来保证，而不是数据库约束
        self.db_pool.updates.register_background_index_update(
            "users_wallet_address",
            index_name="users_wallet_address",
            table="users",
            columns=["wallet_address"],
        )
        
class RegistrationDwebStore(RegistrationStore, RegistrationDwebBackgroundUpdateStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)
    
    async def add_wallet_address_to_user(
        self,
        user_id: str,
        wallet_address: str,
    ) -> str:
        """Adds an access token for the given user.

        Args:
            user_id: The user ID.
            wallet_address: Address of dweb wallet application.
        Raises:
            StoreError if there was a problem adding this.
        Returns:
            The wallet address
        """
        await self.db_pool.simple_update(
            "users",
            keyvalues={"name": user_id},
            updatevalues={"wallet_address": wallet_address},
            desc="add_access_token_to_user",
        )

        return wallet_address