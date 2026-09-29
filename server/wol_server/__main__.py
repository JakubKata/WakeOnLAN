import asyncio
import logging
import os
import sys
from pathlib import Path

import asyncpg
from dotenv import load_dotenv

from .app import WolServer
from .config import ConfigError, Settings
from .context import Services
from .db import Database
from .db.schema import SchemaError
from .handlers import build_dispatcher
from .mailer import Mailer
from .security import Security

SERVER_DIR = Path(__file__).resolve().parents[1]

log = logging.getLogger("wol_server")


async def run(settings: Settings) -> None:
    db = Database(settings.database_url, max_connections=settings.db_pool_size)
    await db.connect()
    try:
        version = await db.migrate()
        log.info("database ready at schema v%d", version)

        mailer = Mailer(settings.smtp) if settings.smtp else None
        if mailer is None:
            log.warning("SMTP_HOST is not set; password reset by e-mail is disabled")
        services = Services.create(db, Security(settings.pepper), mailer=mailer)
        server = WolServer(settings, services, build_dispatcher())
        await server.start()
        try:
            await server.serve_forever()
        finally:
            await server.close()
            if mailer is not None:
                await mailer.close()
    finally:
        await db.close()


def main() -> None:
    load_dotenv(SERVER_DIR / ".env")
    try:
        settings = Settings.from_env(os.environ, base_dir=SERVER_DIR)
    except ConfigError as exc:
        sys.exit(f"configuration error: {exc}")

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run(settings))
    except (SchemaError, asyncpg.PostgresError) as exc:
        sys.exit(f"database error: {exc}")
    except OSError as exc:
        sys.exit(f"startup error: {exc}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
