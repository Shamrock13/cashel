"""Auth blueprint — /login, /logout.

Seed location for future LDAP/OIDC/TACACS+ routes.
"""

import secrets
import time

from flask import Blueprint, redirect, render_template, request, session, url_for

from cashel.settings import get_settings

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@auth_bp.route("/login", methods=["POST"])
def login_post():
    key = request.form.get("api_key", "")
    settings = get_settings()
    stored = settings.get("api_key", "")
    if stored and secrets.compare_digest(key, stored):
        session.clear()
        session["authenticated"] = True
        session["last_seen"] = time.time()
        next_url = request.args.get("next", "")
        # Guard against open-redirect: only accept relative paths
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("index"))
    return render_template(
        "login.html", error="Invalid API key. Please try again."
    ), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
