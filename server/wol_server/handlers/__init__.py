from ..dispatcher import Dispatcher
from . import account, auth, devices, esp, password_reset, targets


def build_dispatcher() -> Dispatcher:
    return Dispatcher([
        auth.router, password_reset.router, account.router, devices.router, targets.router, esp.router,
    ])
