# -*- coding: utf-8 -*-

"""
Authenticator is responsible for authenticating the users,
create the tokens unscoped and scoped, retrieve the role
list inside the projects that they are inserted
"""

__author__ = "Eduardo Sousa <esousa@whitestack.com>"
__date__ = "$27-jul-2018 23:59:59$"

import logging
from base64 import standard_b64decode
from copy import deepcopy
from functools import reduce
from http import HTTPStatus
from time import time

import cherrypy

from authconn import AuthException
from authconn_keystone import AuthconnKeystone
from engine import EngineException


class Authenticator:
    """
    This class should hold all the mechanisms for User Authentication and
    Authorization. Initially it should support Openstack Keystone as a
    backend through a plugin model where more backends can be added and a
    RBAC model to manage permissions on operations.
    """

    def __init__(self, engine):
        """
        Authenticator initializer. Setup the initial state of the object,
        while it waits for the config dictionary and database initialization.

        Note: engine is only here until all the calls can to it can be replaced.

        :param engine: reference to engine object used.
        """
        super().__init__()

        self.engine = engine

        self.backend = None
        self.config = None
        self.db = None
        self.tokens = dict()
        self.logger = logging.getLogger("nbi.authenticator")

    def start(self, config):
        """
        Method to configure the Authenticator object. This method should be called
        after object creation. It is responsible by initializing the selected backend,
        as well as the initialization of the database connection.

        :param config: dictionary containing the relevant parameters for this object.
        """
        self.config = config

        try:
            if not self.backend:
                if config["authentication"]["backend"] == "keystone":
                    self.backend = AuthconnKeystone(self.config["authentication"])
                elif config["authentication"]["backend"] == "internal":
                    pass
                else:
                    raise Exception("No authentication backend defined")
            if not self.db:
                pass
                # TODO: Implement database initialization
                # NOTE: Database needed to store the mappings
        except Exception as e:
            raise AuthException(str(e))

    def init_db(self, target_version='1.0'):
        """
        Check if the database has been initialized. If not, create the required tables
        and insert the predefined mappings between roles and permissions.

        :param target_version: schema version that should be present in the database.
        :return: None if OK, exception if error or version is different.
        """
        pass

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
                    outdata = self.new_token(None, {"username": user, "password": passwd})
                    token = outdata["id"]
                    cherrypy.session['Authorization'] = token
            if self.config["authentication"]["backend"] == "internal":
                return self.engine.authorize(token)
            else:
                try:
                    self.backend.validate_token(token)
                    return self.tokens[token]
                except AuthException:
                    self.del_token(token)
                    raise
        except EngineException as e:
            if cherrypy.session.get('Authorization'):
                del cherrypy.session['Authorization']
            cherrypy.response.headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(e)
            raise AuthException(str(e))

    def new_token(self, session, indata, remote):
        if self.config["authentication"]["backend"] == "internal":
            return self.engine.new_token(session, indata, remote)
        else:
            if indata.get("username"):
                token, projects = self.backend.authenticate_with_user_password(
                    indata.get("username"), indata.get("password"))
            elif session:
                token, projects = self.backend.authenticate_with_token(
                    session.get("id"), indata.get("project_id"))
            else:
                raise AuthException("Provide credentials: username/password or Authorization Bearer token",
                                    http_code=HTTPStatus.UNAUTHORIZED)

            if indata.get("project_id"):
                project_id = indata.get("project_id")
                if project_id not in projects:
                    raise AuthException("Project {} not allowed for this user".format(project_id),
                                        http_code=HTTPStatus.UNAUTHORIZED)
            else:
                project_id = projects[0]

            if project_id == "admin":
                session_admin = True
            else:
                session_admin = reduce(lambda x, y: x or (True if y == "admin" else False),
                                       projects, False)

            now = time()
            new_session = {
                "_id": token,
                "id": token,
                "issued_at": now,
                "expires": now+3600,
                "project_id": project_id,
                "username": indata.get("username") if not session else session.get("username"),
                "remote_port": remote.port,
                "admin": session_admin
            }

            if remote.name:
                new_session["remote_host"] = remote.name
            elif remote.ip:
                new_session["remote_host"] = remote.ip

            self.tokens[token] = new_session

            return deepcopy(new_session)

    def get_token_list(self, session):
        if self.config["authentication"]["backend"] == "internal":
            return self.engine.get_token_list(session)
        else:
            return [deepcopy(token) for token in self.tokens.values()
                    if token["username"] == session["username"]]

    def get_token(self, session, token):
        if self.config["authentication"]["backend"] == "internal":
            return self.engine.get_token(session, token)
        else:
            token_value = self.tokens.get(token)
            if not token_value:
                raise EngineException("token not found", http_code=HTTPStatus.NOT_FOUND)
            if token_value["username"] != session["username"] and not session["admin"]:
                raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
            return token_value

    def del_token(self, token):
        if self.config["authentication"]["backend"] == "internal":
            return self.engine.del_token(token)
        else:
            try:
                self.backend.revoke_token(token)
                del self.tokens[token]
                return "token '{}' deleted".format(token)
            except KeyError:
                raise EngineException("Token '{}' not found".format(token), http_code=HTTPStatus.NOT_FOUND)
