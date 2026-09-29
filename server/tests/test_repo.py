import asyncio

import pytest

from helpers import create_user, requires_database, temporary_database, temporary_services
from wol_server.db.repo import MAX_DEVICES_PER_USER, MAX_SESSIONS_PER_USER
from wol_server.db.schema import SchemaError
from wol_server.errors import CommandError
from wol_server.protocol import Err

pytestmark = requires_database


def with_services(scenario):
    async def runner():
        async with temporary_services() as services:
            await scenario(services)

    asyncio.run(runner())


def test_migrate_is_idempotent_and_refuses_newer_schema():
    async def scenario():
        async with temporary_database() as db:
            assert await db.migrate() == 3
            await db.pool.execute("INSERT INTO schema_migrations (version) VALUES (99)")
            with pytest.raises(SchemaError):
                await db.migrate()

    asyncio.run(scenario())


def test_user_names_are_case_insensitive_and_unique():
    async def scenario(services):
        await services.users.register("Alice", "a@x.pl", "h", "t1", ttl=60)
        with pytest.raises(CommandError) as exc:
            await services.users.register("alice", "other@x.pl", "h", "t2", ttl=60)
        assert exc.value.code is Err.ACCOUNT_EXISTS
        with pytest.raises(CommandError):
            await services.users.register("bob", "A@X.PL", "h", "t3", ttl=60)
        assert (await services.users.by_name("ALICE")).name == "Alice"

    with_services(scenario)


def test_rename_conflict():
    async def scenario(services):
        await create_user(services, "alice", "a@x.pl", "h")
        bob = await create_user(services, "bob", "b@x.pl", "h")
        with pytest.raises(CommandError) as exc:
            await services.users.rename(bob, "Alice")
        assert exc.value.code is Err.NAME_TAKEN

    with_services(scenario)


def test_sessions_refresh_expire_and_cap():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.sessions.create(user, "live", ttl=60, epoch=0)
        await services.sessions.create(user, "dead", ttl=-1, epoch=0)
        assert await services.sessions.exists("live")
        assert not await services.sessions.exists("dead")
        assert await services.sessions.refresh("live", 60) == user
        assert await services.sessions.refresh("dead", 60) is None
        assert await services.sessions.refresh("unknown", 60) is None
        assert await services.sessions.purge_expired() == 1

        for i in range(MAX_SESSIONS_PER_USER + 5):
            await services.sessions.create(user, f"t{i}", ttl=60, epoch=0)
        assert await services.db.pool.fetchval("SELECT count(*) FROM sessions") == MAX_SESSIONS_PER_USER

    with_services(scenario)


def test_session_is_not_created_for_a_stale_epoch():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        epoch = (await services.users.by_id(user)).session_epoch
        await services.sessions.create(user, "before", ttl=60, epoch=epoch)

        new_epoch = await services.users.change_password(user, "h2")
        assert new_epoch == epoch + 1
        assert not await services.sessions.exists("before")
        assert not await services.sessions.create(user, "late", ttl=60, epoch=epoch)
        assert not await services.sessions.exists("late")
        assert await services.sessions.create(user, "fresh", ttl=60, epoch=new_epoch)
        assert not await services.sessions.create(user + 1000, "nobody", ttl=60, epoch=0)

    with_services(scenario)


def test_revocation_removes_sessions_resets_and_claims():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.sessions.create(user, "tok", ttl=60, epoch=0)
        await services.resets.create(user, "code", ttl=60)
        await services.claims.create(user, "claim", "ESP", ttl=60)
        assert await services.users.revoke_all(user) == 1
        for table in ("sessions", "password_resets", "claims"):
            assert await services.db.pool.fetchval(f"SELECT count(*) FROM {table}") == 0
        assert (await services.users.by_id(user)).password_hash == "h"

    with_services(scenario)


def test_register_creates_user_and_session_together():
    async def scenario(services):
        user = await services.users.register("alice", "a@x.pl", "h", "tok", 60)
        assert await services.sessions.refresh("tok", 60) == user
        with pytest.raises(CommandError) as exc:
            await services.users.register("ALICE", "b@x.pl", "h", "tok2", 60)
        assert exc.value.code is Err.ACCOUNT_EXISTS
        assert not await services.sessions.exists("tok2")

    with_services(scenario)


def test_rehash_does_not_overwrite_a_changed_password():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "old")
        await services.users.change_password(user, "changed")
        await services.users.rehash_password(user, "old", "rehashed-old")
        assert (await services.users.by_id(user)).password_hash == "changed"

    with_services(scenario)


def test_claim_is_single_use_and_replaced():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.claims.create(user, "claim-1", "ESP", ttl=60)
        await services.claims.create(user, "claim-2", "ESP", ttl=60)
        assert await services.devices.redeem_claim("claim-1", "dev1", "s") is None
        device = await services.devices.redeem_claim("claim-2", "dev1", "s")
        assert device.user_id == user and device.name == "ESP"
        assert await services.devices.redeem_claim("claim-2", "dev2", "s") is None

    with_services(scenario)


def test_expired_claim_is_rejected():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.claims.create(user, "claim", "ESP", ttl=-1)
        assert await services.devices.redeem_claim("claim", "dev", "s") is None

    with_services(scenario)


def test_device_limit():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        for i in range(MAX_DEVICES_PER_USER):
            await services.claims.create(user, f"c{i}", "ESP", ttl=60)
            await services.devices.redeem_claim(f"c{i}", f"d{i}", "s")
        with pytest.raises(CommandError) as exc:
            await services.claims.create(user, "extra", "ESP", ttl=60)
        assert exc.value.code is Err.LIMIT_REACHED

    with_services(scenario)


def test_concurrent_claims_respect_device_limit():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        for i in range(MAX_DEVICES_PER_USER - 1):
            await services.claims.create(user, f"c{i}", "ESP", ttl=60)
            await services.devices.redeem_claim(f"c{i}", f"d{i}", "s")

        async def claim_and_redeem(n):
            await services.claims.create(user, f"race{n}", "ESP", ttl=60)
            return await services.devices.redeem_claim(f"race{n}", f"race-dev{n}", "s")

        await asyncio.gather(*(claim_and_redeem(n) for n in range(5)), return_exceptions=True)
        count = await services.db.pool.fetchval("SELECT count(*) FROM devices WHERE user_id = $1", user)
        assert count == MAX_DEVICES_PER_USER

    with_services(scenario)


def test_secret_rotation():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.claims.create(user, "c", "ESP", ttl=60)
        await services.devices.redeem_claim("c", "dev", "old")
        await services.devices.stage_secret(user, "dev", "new")
        assert await services.devices.authenticate("dev", "new") is not None
        assert await services.devices.authenticate("dev", "old") is None
        assert await services.devices.authenticate("dev", "wrong") is None

        # Already promoted by authenticate(): still reported as current.
        assert await services.devices.promote_secret("dev", "new")
        await services.devices.stage_secret(user, "dev", "a")
        await services.devices.stage_secret(user, "dev", "b")
        assert not await services.devices.promote_secret("dev", "a")
        assert await services.devices.promote_secret("dev", "b")
        assert await services.devices.authenticate("dev", "b") is not None

    with_services(scenario)


def test_login_with_current_secret_drops_staged_one():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.claims.create(user, "c", "ESP", ttl=60)
        await services.devices.redeem_claim("c", "dev", "old")
        await services.devices.stage_secret(user, "dev", "new")
        assert await services.devices.authenticate("dev", "old") is not None
        assert await services.devices.authenticate("dev", "new") is None
        assert await services.devices.authenticate("dev", "old") is not None

    with_services(scenario)


def test_targets_are_scoped_and_survive_device_removal():
    async def scenario(services):
        alice = await create_user(services, "alice", "a@x.pl", "h")
        bob = await create_user(services, "bob", "b@x.pl", "h")
        await services.claims.create(alice, "c", "ESP", ttl=60)
        await services.devices.redeem_claim("c", "dev", "s")

        target = await services.targets.add(alice, "dev", "AA:BB:CC:DD:EE:FF", "PC")
        with pytest.raises(CommandError) as exc:
            await services.targets.add(alice, "dev", "AA:BB:CC:DD:EE:FF", "PC again")
        assert exc.value.code is Err.DUPLICATE
        with pytest.raises(CommandError):
            await services.targets.add(bob, "dev", "11:22:33:44:55:66", "hijack")
        assert await services.targets.get(bob, target.id) is None
        with pytest.raises(CommandError):
            await services.targets.remove(bob, target.id)

        await services.devices.delete(alice, "dev")
        orphan = await services.targets.get(alice, target.id)
        assert orphan is not None and orphan.device_id is None

    with_services(scenario)


def test_delete_user_cascades():
    async def scenario(services):
        user = await create_user(services, "alice", "a@x.pl", "h")
        await services.sessions.create(user, "tok", ttl=60, epoch=0)
        await services.claims.create(user, "c", "ESP", ttl=60)
        await services.devices.redeem_claim("c", "dev", "s")
        await services.targets.add(user, "dev", "AA:BB:CC:DD:EE:FF", "PC")
        await services.users.delete(user)
        for table in ("sessions", "claims", "devices", "targets"):
            assert await services.db.pool.fetchval(f"SELECT count(*) FROM {table}") == 0

    with_services(scenario)
