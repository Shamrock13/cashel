"""Shared Flask extension instances.

Defined here (rather than in web.py) so blueprints can import limiter/csrf
without creating a circular import back into cashel.web.

web.py calls csrf.init_app(app) and limiter.init_app(app) after creating the
Flask app object.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

csrf: CSRFProtect = CSRFProtect()
limiter: Limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)
