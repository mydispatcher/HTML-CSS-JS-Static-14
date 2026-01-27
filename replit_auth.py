import jwt
import os
import uuid
from functools import wraps
from urllib.parse import urlencode

from flask import g, session, redirect, request, render_template, url_for
from flask_dance.consumer import (
    OAuth2ConsumerBlueprint,
    oauth_authorized,
    oauth_error,
)
from flask_dance.consumer.storage import BaseStorage
from flask_login import LoginManager, login_user, logout_user, current_user
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from sqlalchemy.exc import NoResultFound
from werkzeug.local import LocalProxy

def make_replit_blueprint():
    from app import db, User
    repl_id = os.environ.get('REPL_ID', 'dev-repl-id')
    issuer_url = os.environ.get('ISSUER_URL', "https://replit.com/oidc")

    replit_bp = OAuth2ConsumerBlueprint(
        "replit_auth",
        __name__,
        client_id=repl_id,
        client_secret=None,
        base_url=issuer_url,
        authorization_url_params={
            "prompt": "login consent",
        },
        token_url=issuer_url + "/token",
        token_url_params={
            "auth": (),
            "include_client_id": True,
        },
        auto_refresh_url=issuer_url + "/token",
        auto_refresh_kwargs={
            "client_id": repl_id,
        },
        authorization_url=issuer_url + "/auth",
        use_pkce=True,
        code_challenge_method="S256",
        scope=["openid", "profile", "email", "offline_access"],
        storage=UserSessionStorage(),
    )

    @replit_bp.route("/logout")
    def logout():
        logout_user()
        end_session_endpoint = issuer_url + "/session/end"
        encoded_params = urlencode({
            "client_id": repl_id,
            "post_logout_redirect_uri": request.url_root,
        })
        return redirect(f"{end_session_endpoint}?{encoded_params}")

    return replit_bp

class UserSessionStorage(BaseStorage):
    def get(self, blueprint):
        return session.get(f"{blueprint.name}_oauth_token")

    def set(self, blueprint, token):
        session[f"{blueprint.name}_oauth_token"] = token

    def delete(self, blueprint):
        session.pop(f"{blueprint.name}_oauth_token", None)

@oauth_authorized.connect
def on_logged_in(blueprint, token):
    from app import db, User
    user_claims = jwt.decode(token['id_token'], options={"verify_signature": False})
    
    email = user_claims.get('email')
    sub = user_claims.get('sub')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        username = email.split('@')[0]
        user = User(username=username, email=email)
        user.set_password(str(uuid.uuid4()))
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('index'))

replit = LocalProxy(lambda: g.flask_dance_replit)
