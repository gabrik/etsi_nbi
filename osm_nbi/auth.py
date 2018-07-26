import cherrypy
from base64 import standard_b64decode
from http import HTTPStatus


from engine import EngineException

__author__ = "Eduardo Sousa <eduardosousa@av.it.pt>"


class AuthenticatorException(Exception):
    def __init__(self, message, http_code=HTTPStatus.UNAUTHORIZED):
        self.http_code = http_code
        Exception.__init__(self, message)


class Authenticator(object):
    def __init__(self, engine):
        super().__init__()

        self.engine = engine

    def authorize(self):
        token = None
        user_passwd64 = None
        try:
            # 1. Get token Authorization bearer
            auth = cherrypy.request.headers.get("Authorization")
            if auth:
                auth_list = auth.split(" ")
                if auth_list[0].lower() == "bearer":
                    token = auth_list[-1]
                elif auth_list[0].lower() == "basic":
                    user_passwd64 = auth_list[-1]
            if not token:
                if cherrypy.session.get("Authorization"):
                    # 2. Try using session before request a new token. If not, basic authentication will generate
                    token = cherrypy.session.get("Authorization")
                    if token == "logout":
                        token = None  # force Unauthorized response to insert user pasword again
                elif user_passwd64 and cherrypy.request.config.get("auth.allow_basic_authentication"):
                    # 3. Get new token from user password
                    user = None
                    passwd = None
                    try:
                        user_passwd = standard_b64decode(user_passwd64).decode()
                        user, _, passwd = user_passwd.partition(":")
                    except Exception:
                        pass
                    outdata = self.engine.new_token(None, {"username": user, "password": passwd})
                    token = outdata["id"]
                    cherrypy.session['Authorization'] = token
            # 4. Get token from cookie
            # if not token:
            #     auth_cookie = cherrypy.request.cookie.get("Authorization")
            #     if auth_cookie:
            #         token = auth_cookie.value
            return self.engine.authorize(token)
        except EngineException as e:
            if cherrypy.session.get('Authorization'):
                del cherrypy.session['Authorization']
            cherrypy.response.headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(e)
            raise AuthenticatorException(str(e))

    def new_token(self, session, indata, remote):
        return self.engine.new_token(session, indata, remote)

    def get_token_list(self, session):
        return self.engine.get_token_list(session)

    def get_token(self, session, token_id):
        return self.engine.get_token(session, token_id)

    def del_token(self, token_id):
        return self.engine.del_token(token_id)
