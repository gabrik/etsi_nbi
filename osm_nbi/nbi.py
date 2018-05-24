#!/usr/bin/python3
# -*- coding: utf-8 -*-

import cherrypy
import time
import json
import yaml
import html_out as html
import logging
import logging.handlers
import getopt
import sys
from engine import Engine, EngineException
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from base64 import standard_b64decode
from http import HTTPStatus
from codecs import getreader
from os import environ, path

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"

# TODO consider to remove and provide version using the static version file
__version__ = "0.1.3"
version_date = "Apr 2018"
database_version = '1.0'

"""
North Bound Interface  (O: OSM specific; 5,X: SOL005 not implemented yet; O5: SOL005 implemented)
URL: /osm                                                       GET     POST    PUT     DELETE  PATCH
        /nsd/v1                                                 O       O
            /ns_descriptors_content                             O       O
                /<nsdInfoId>                                    O       O       O       O
            /ns_descriptors                                     O5      O5
                /<nsdInfoId>                                    O5                      O5      5
                    /nsd_content                                O5              O5
                    /nsd                                        O
                    /artifacts[/<artifactPath>]                 O
            /pnf_descriptors                                    5       5
                /<pnfdInfoId>                                   5                       5       5
                    /pnfd_content                               5               5
            /subscriptions                                      5       5
                /<subscriptionId>                               5                       X

        /vnfpkgm/v1
            /vnf_packages_content                               O       O
                /<vnfPkgId>                                     O                       O
            /vnf_packages                                       O5      O5
                /<vnfPkgId>                                     O5                      O5      5
                    /package_content                            O5               O5
                        /upload_from_uri                                X
                    /vnfd                                       O5
                    /artifacts[/<artifactPath>]                 O5
            /subscriptions                                      X       X
                /<subscriptionId>                               X                       X

        /nslcm/v1
            /ns_instances_content                               O       O
                /<nsInstanceId>                                 O                       O
            /ns_instances                                       5       5
                /<nsInstanceId>                                 O5                      O5
                    instantiate                                         O5
                    terminate                                           O5
                    action                                              O
                    scale                                               O5
                    heal                                                5
            /ns_lcm_op_occs                                     5       5
                /<nsLcmOpOccId>                                 5                       5       5
                    TO BE COMPLETED                             5               5
            /vnfrs                                              O
                /<vnfrId>                                       O
            /subscriptions                                      5       5
                /<subscriptionId>                               5                       X
        /admin/v1
            /tokens                                             O       O
                /<id>                                           O                       O
            /users                                              O       O
                /<id>                                           O                       O
            /projects                                           O       O
                /<id>                                           O                       O
            /vims_accounts  (also vims for compatibility)       O       O
                /<id>                                           O                       O       O
            /sdns                                               O       O
                /<id>                                           O                       O       O

query string:
    Follows SOL005 section 4.3.2 It contains extra METHOD to override http method, FORCE to force.
    For filtering inside array, it must select the element of the array, or add ANYINDEX to apply the filtering over any
    item of the array, that is, pass if any item of the array pass the filter.
    It allows both ne and neq for not equal
    TODO: 4.3.3 Attribute selectors
        all_fields, fields=x,y,.., exclude_default, exclude_fields=x,y,...
        (none)	… same as “exclude_default”
        all_fields	… all attributes.
        fields=<list>	… all attributes except all complex attributes with minimum cardinality of zero that are not
        conditionally mandatory, and that are not provided in <list>.
        exclude_fields=<list>	… all attributes except those complex attributes with a minimum cardinality of zero that
        are not conditionally mandatory, and that are provided in <list>.
        exclude_default	… all attributes except those complex attributes with a minimum cardinality of zero that are not
        conditionally mandatory, and that are part of the "default exclude set" defined in the present specification for
        the particular resource
        exclude_default and include=<list>	… all attributes except those complex attributes with a minimum cardinality
        of zero that are not conditionally mandatory and that are part of the "default exclude set" defined in the
        present specification for the particular resource, but that are not part of <list>
Header field name	Reference	Example	Descriptions
    Accept	IETF RFC 7231 [19]	application/json	Content-Types that are acceptable for the response.
    This header field shall be present if the response is expected to have a non-empty message body.
    Content-Type	IETF RFC 7231 [19]	application/json	The MIME type of the body of the request.
    This header field shall be present if the request has a non-empty message body.
    Authorization	IETF RFC 7235 [22]	Bearer mF_9.B5f-4.1JqM 	The authorization token for the request.
    Details are specified in clause 4.5.3.
    Range	IETF RFC 7233 [21]	1000-2000	Requested range of bytes from a file
Header field name	Reference	Example	Descriptions
    Content-Type	IETF RFC 7231 [19]	application/json	The MIME type of the body of the response.
    This header field shall be present if the response has a non-empty message body.
    Location	IETF RFC 7231 [19]	http://www.example.com/vnflcm/v1/vnf_instances/123	Used in redirection, or when a
    new resource has been created.
    This header field shall be present if the response status code is 201 or 3xx.
    In the present document this header field is also used if the response status code is 202 and a new resource was
    created.
    WWW-Authenticate	IETF RFC 7235 [22]	Bearer realm="example"	Challenge if the corresponding HTTP request has not
    provided authorization, or error details if the corresponding HTTP request has provided an invalid authorization
    token.
    Accept-Ranges	IETF RFC 7233 [21]	bytes	Used by the Server to signal whether or not it supports ranges for
    certain resources.
    Content-Range	IETF RFC 7233 [21]	bytes 21010-47021/ 47022	Signals the byte range that is contained in the
    response, and the total length of the file.
    Retry-After	IETF RFC 7231 [19]	Fri, 31 Dec 1999 23:59:59 GMT
"""


class NbiException(Exception):

    def __init__(self, message, http_code=HTTPStatus.METHOD_NOT_ALLOWED):
        Exception.__init__(self, message)
        self.http_code = http_code


class Server(object):
    instance = 0
    # to decode bytes to str
    reader = getreader("utf-8")

    def __init__(self):
        self.instance += 1
        self.engine = Engine()
        self.valid_methods = {   # contains allowed URL and methods
            "admin": {
                "v1": {
                    "tokens": {"METHODS": ("GET", "POST", "DELETE"),
                               "<ID>": {"METHODS": ("GET", "DELETE")}
                               },
                    "users": {"METHODS": ("GET", "POST"),
                              "<ID>": {"METHODS": ("GET", "POST", "DELETE")}
                              },
                    "projects": {"METHODS": ("GET", "POST"),
                                 "<ID>": {"METHODS": ("GET", "DELETE")}
                                 },
                    "vims": {"METHODS": ("GET", "POST"),
                             "<ID>": {"METHODS": ("GET", "DELETE", "PATCH", "PUT")}
                             },
                    "vim_accounts": {"METHODS": ("GET", "POST"),
                                     "<ID>": {"METHODS": ("GET", "DELETE", "PATCH", "PUT")}
                                     },
                    "sdns": {"METHODS": ("GET", "POST"),
                             "<ID>": {"METHODS": ("GET", "DELETE", "PATCH", "PUT")}
                             },
                }
            },
            "nsd": {
                "v1": {
                    "ns_descriptors_content": {"METHODS": ("GET", "POST"),
                                               "<ID>": {"METHODS": ("GET", "PUT", "DELETE")}
                                               },
                    "ns_descriptors": {"METHODS": ("GET", "POST"),
                                       "<ID>": {"METHODS": ("GET", "DELETE"), "TODO": "PATCH",
                                                "nsd_content": {"METHODS": ("GET", "PUT")},
                                                "nsd": {"METHODS": "GET"},  # descriptor inside package
                                                "artifacts": {"*": {"METHODS": "GET"}}
                                                }
                                       },
                    "pnf_descriptors": {"TODO": ("GET", "POST"),
                                        "<ID>": {"TODO": ("GET", "DELETE", "PATCH"),
                                                 "pnfd_content": {"TODO": ("GET", "PUT")}
                                                 }
                                        },
                    "subscriptions": {"TODO": ("GET", "POST"),
                                      "<ID>": {"TODO": ("GET", "DELETE")}
                                      },
                }
            },
            "vnfpkgm": {
                "v1": {
                    "vnf_packages_content": {"METHODS": ("GET", "POST"),
                                             "<ID>": {"METHODS": ("GET", "PUT", "DELETE")}
                                             },
                    "vnf_packages": {"METHODS": ("GET", "POST"),
                                     "<ID>": {"METHODS": ("GET", "DELETE"), "TODO": "PATCH",  # GET: vnfPkgInfo
                                              "package_content": {"METHODS": ("GET", "PUT"),         # package
                                                                  "upload_from_uri": {"TODO": "POST"}
                                                                  },
                                              "vnfd": {"METHODS": "GET"},                    # descriptor inside package
                                              "artifacts": {"*": {"METHODS": "GET"}}
                                              }
                                     },
                    "subscriptions": {"TODO": ("GET", "POST"),
                                      "<ID>": {"TODO": ("GET", "DELETE")}
                                      },
                }
            },
            "nslcm": {
                "v1": {
                    "ns_instances_content": {"METHODS": ("GET", "POST"),
                                             "<ID>": {"METHODS": ("GET", "DELETE")}
                                             },
                    "ns_instances": {"METHODS": ("GET", "POST"),
                                     "<ID>": {"METHODS": ("GET", "DELETE"),
                                              "scale": {"TODO": "POST"},
                                              "terminate": {"METHODS": "POST"},
                                              "instantiate": {"METHODS": "POST"},
                                              "action": {"METHODS": "POST"},
                                              }
                                     },
                    "ns_lcm_op_occs": {"METHODS": "GET",
                                       "<ID>": {"METHODS": "GET"},
                                       },
                    "vnfrs": {"METHODS": ("GET"),
                              "<ID>": {"METHODS": ("GET")}
                              },
                }
            },
        }

    def _authorization(self):
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
                        token = None   # force Unauthorized response to insert user pasword again
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
            raise

    def _format_in(self, kwargs):
        try:
            indata = None
            if cherrypy.request.body.length:
                error_text = "Invalid input format "

                if "Content-Type" in cherrypy.request.headers:
                    if "application/json" in cherrypy.request.headers["Content-Type"]:
                        error_text = "Invalid json format "
                        indata = json.load(self.reader(cherrypy.request.body))
                    elif "application/yaml" in cherrypy.request.headers["Content-Type"]:
                        error_text = "Invalid yaml format "
                        indata = yaml.load(cherrypy.request.body)
                    elif "application/binary" in cherrypy.request.headers["Content-Type"] or \
                         "application/gzip" in cherrypy.request.headers["Content-Type"] or \
                         "application/zip" in cherrypy.request.headers["Content-Type"] or \
                         "text/plain" in cherrypy.request.headers["Content-Type"]:
                        indata = cherrypy.request.body  # .read()
                    elif "multipart/form-data" in cherrypy.request.headers["Content-Type"]:
                        if "descriptor_file" in kwargs:
                            filecontent = kwargs.pop("descriptor_file")
                            if not filecontent.file:
                                raise NbiException("empty file or content", HTTPStatus.BAD_REQUEST)
                            indata = filecontent.file  # .read()
                            if filecontent.content_type.value:
                                cherrypy.request.headers["Content-Type"] = filecontent.content_type.value
                    else:
                        # raise cherrypy.HTTPError(HTTPStatus.Not_Acceptable,
                        #                          "Only 'Content-Type' of type 'application/json' or
                        # 'application/yaml' for input format are available")
                        error_text = "Invalid yaml format "
                        indata = yaml.load(cherrypy.request.body)
                else:
                    error_text = "Invalid yaml format "
                    indata = yaml.load(cherrypy.request.body)
            if not indata:
                indata = {}

            format_yaml = False
            if cherrypy.request.headers.get("Query-String-Format") == "yaml":
                format_yaml = True

            for k, v in kwargs.items():
                if isinstance(v, str):
                    if v == "":
                        kwargs[k] = None
                    elif format_yaml:
                        try:
                            kwargs[k] = yaml.load(v)
                        except Exception:
                            pass
                    elif k.endswith(".gt") or k.endswith(".lt") or k.endswith(".gte") or k.endswith(".lte"):
                        try:
                            kwargs[k] = int(v)
                        except Exception:
                            try:
                                kwargs[k] = float(v)
                            except Exception:
                                pass
                    elif v.find(",") > 0:
                        kwargs[k] = v.split(",")
                elif isinstance(v, (list, tuple)):
                    for index in range(0, len(v)):
                        if v[index] == "":
                            v[index] = None
                        elif format_yaml:
                            try:
                                v[index] = yaml.load(v[index])
                            except Exception:
                                pass

            return indata
        except (ValueError, yaml.YAMLError) as exc:
            raise NbiException(error_text + str(exc), HTTPStatus.BAD_REQUEST)
        except KeyError as exc:
            raise NbiException("Query string error: " + str(exc), HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            raise NbiException(error_text + str(exc), HTTPStatus.BAD_REQUEST)

    @staticmethod
    def _format_out(data, session=None, _format=None):
        """
        return string of dictionary data according to requested json, yaml, xml. By default json
        :param data: response to be sent. Can be a dict, text or file
        :param session:
        :param _format: The format to be set as Content-Type ir data is a file
        :return: None
        """
        accept = cherrypy.request.headers.get("Accept")
        if data is None:
            if accept and "text/html" in accept:
                return html.format(data, cherrypy.request, cherrypy.response, session)
            # cherrypy.response.status = HTTPStatus.NO_CONTENT.value
            return
        elif hasattr(data, "read"):  # file object
            if _format:
                cherrypy.response.headers["Content-Type"] = _format
            elif "b" in data.mode:  # binariy asssumig zip
                cherrypy.response.headers["Content-Type"] = 'application/zip'
            else:
                cherrypy.response.headers["Content-Type"] = 'text/plain'
            # TODO check that cherrypy close file. If not implement pending things to close  per thread next
            return data
        if accept:
            if "application/json" in accept:
                cherrypy.response.headers["Content-Type"] = 'application/json; charset=utf-8'
                a = json.dumps(data, indent=4) + "\n"
                return a.encode("utf8")
            elif "text/html" in accept:
                return html.format(data, cherrypy.request, cherrypy.response, session)

            elif "application/yaml" in accept or "*/*" in accept or "text/plain" in accept:
                pass
            else:
                raise cherrypy.HTTPError(HTTPStatus.NOT_ACCEPTABLE.value,
                                         "Only 'Accept' of type 'application/json' or 'application/yaml' "
                                         "for output format are available")
        cherrypy.response.headers["Content-Type"] = 'application/yaml'
        return yaml.safe_dump(data, explicit_start=True, indent=4, default_flow_style=False, tags=False,
                              encoding='utf-8', allow_unicode=True)  # , canonical=True, default_style='"'

    @cherrypy.expose
    def index(self, *args, **kwargs):
        session = None
        try:
            if cherrypy.request.method == "GET":
                session = self._authorization()
                outdata = "Index page"
            else:
                raise cherrypy.HTTPError(HTTPStatus.METHOD_NOT_ALLOWED.value,
                                         "Method {} not allowed for tokens".format(cherrypy.request.method))

            return self._format_out(outdata, session)

        except EngineException as e:
            cherrypy.log("index Exception {}".format(e))
            cherrypy.response.status = e.http_code.value
            return self._format_out("Welcome to OSM!", session)

    @cherrypy.expose
    def version(self, *args, **kwargs):
        # TODO consider to remove and provide version using the static version file
        global __version__, version_date
        try:
            if cherrypy.request.method != "GET":
                raise NbiException("Only method GET is allowed", HTTPStatus.METHOD_NOT_ALLOWED)
            elif args or kwargs:
                raise NbiException("Invalid URL or query string for version", HTTPStatus.METHOD_NOT_ALLOWED)
            return __version__ + " " + version_date
        except NbiException as e:
            cherrypy.response.status = e.http_code.value
            problem_details = {
                "code": e.http_code.name,
                "status": e.http_code.value,
                "detail": str(e),
            }
            return self._format_out(problem_details, None)

    @cherrypy.expose
    def token(self, method, token_id=None, kwargs=None):
        session = None
        # self.engine.load_dbase(cherrypy.request.app.config)
        indata = self._format_in(kwargs)
        if not isinstance(indata, dict):
            raise NbiException("Expected application/yaml or application/json Content-Type", HTTPStatus.BAD_REQUEST)
        try:
            if method == "GET":
                session = self._authorization()
                if token_id:
                    outdata = self.engine.get_token(session, token_id)
                else:
                    outdata = self.engine.get_token_list(session)
            elif method == "POST":
                try:
                    session = self._authorization()
                except Exception:
                    session = None
                if kwargs:
                    indata.update(kwargs)
                outdata = self.engine.new_token(session, indata, cherrypy.request.remote)
                session = outdata
                cherrypy.session['Authorization'] = outdata["_id"]
                self._set_location_header("admin", "v1", "tokens", outdata["_id"])
                # cherrypy.response.cookie["Authorization"] = outdata["id"]
                # cherrypy.response.cookie["Authorization"]['expires'] = 3600
            elif method == "DELETE":
                if not token_id and "id" in kwargs:
                    token_id = kwargs["id"]
                elif not token_id:
                    session = self._authorization()
                    token_id = session["_id"]
                outdata = self.engine.del_token(token_id)
                session = None
                cherrypy.session['Authorization'] = "logout"
                # cherrypy.response.cookie["Authorization"] = token_id
                # cherrypy.response.cookie["Authorization"]['expires'] = 0
            else:
                raise NbiException("Method {} not allowed for token".format(method), HTTPStatus.METHOD_NOT_ALLOWED)
            return self._format_out(outdata, session)
        except (NbiException, EngineException, DbException) as e:
            cherrypy.log("tokens Exception {}".format(e))
            cherrypy.response.status = e.http_code.value
            problem_details = {
                "code": e.http_code.name,
                "status": e.http_code.value,
                "detail": str(e),
            }
            return self._format_out(problem_details, session)

    @cherrypy.expose
    def test(self, *args, **kwargs):
        thread_info = None
        if args and args[0] == "help":
            return "<html><pre>\ninit\nfile/<name>  download file\ndb-clear/table\nprune\nlogin\nlogin2\n"\
                   "sleep/<time>\nmessage/topic\n</pre></html>"

        elif args and args[0] == "init":
            try:
                # self.engine.load_dbase(cherrypy.request.app.config)
                self.engine.create_admin()
                return "Done. User 'admin', password 'admin' created"
            except Exception:
                cherrypy.response.status = HTTPStatus.FORBIDDEN.value
                return self._format_out("Database already initialized")
        elif args and args[0] == "file":
            return cherrypy.lib.static.serve_file(cherrypy.tree.apps['/osm'].config["storage"]["path"] + "/" + args[1],
                                                  "text/plain", "attachment")
        elif args and args[0] == "file2":
            f_path = cherrypy.tree.apps['/osm'].config["storage"]["path"] + "/" + args[1]
            f = open(f_path, "r")
            cherrypy.response.headers["Content-type"] = "text/plain"
            return f

        elif len(args) == 2 and args[0] == "db-clear":
            return self.engine.del_item_list({"project_id": "admin"}, args[1], {})
        elif args and args[0] == "prune":
            return self.engine.prune()
        elif args and args[0] == "login":
            if not cherrypy.request.headers.get("Authorization"):
                cherrypy.response.headers["WWW-Authenticate"] = 'Basic realm="Access to OSM site", charset="UTF-8"'
                cherrypy.response.status = HTTPStatus.UNAUTHORIZED.value
        elif args and args[0] == "login2":
            if not cherrypy.request.headers.get("Authorization"):
                cherrypy.response.headers["WWW-Authenticate"] = 'Bearer realm="Access to OSM site"'
                cherrypy.response.status = HTTPStatus.UNAUTHORIZED.value
        elif args and args[0] == "sleep":
            sleep_time = 5
            try:
                sleep_time = int(args[1])
            except Exception:
                cherrypy.response.status = HTTPStatus.FORBIDDEN.value
                return self._format_out("Database already initialized")
            thread_info = cherrypy.thread_data
            print(thread_info)
            time.sleep(sleep_time)
            # thread_info
        elif len(args) >= 2 and args[0] == "message":
            topic = args[1]
            return_text = "<html><pre>{} ->\n".format(topic)
            try:
                if cherrypy.request.method == 'POST':
                    to_send = yaml.load(cherrypy.request.body)
                    for k, v in to_send.items():
                        self.engine.msg.write(topic, k, v)
                        return_text += "  {}: {}\n".format(k, v)
                elif cherrypy.request.method == 'GET':
                    for k, v in kwargs.items():
                        self.engine.msg.write(topic, k, yaml.load(v))
                        return_text += "  {}: {}\n".format(k, yaml.load(v))
            except Exception as e:
                return_text += "Error: " + str(e)
            return_text += "</pre></html>\n"
            return return_text

        return_text = (
            "<html><pre>\nheaders:\n  args: {}\n".format(args) +
            "  kwargs: {}\n".format(kwargs) +
            "  headers: {}\n".format(cherrypy.request.headers) +
            "  path_info: {}\n".format(cherrypy.request.path_info) +
            "  query_string: {}\n".format(cherrypy.request.query_string) +
            "  session: {}\n".format(cherrypy.session) +
            "  cookie: {}\n".format(cherrypy.request.cookie) +
            "  method: {}\n".format(cherrypy.request.method) +
            " session: {}\n".format(cherrypy.session.get('fieldname')) +
            "  body:\n")
        return_text += "    length: {}\n".format(cherrypy.request.body.length)
        if cherrypy.request.body.length:
            return_text += "    content: {}\n".format(
                str(cherrypy.request.body.read(int(cherrypy.request.headers.get('Content-Length', 0)))))
        if thread_info:
            return_text += "thread: {}\n".format(thread_info)
        return_text += "</pre></html>"
        return return_text

    def _check_valid_url_method(self, method, *args):
        if len(args) < 3:
            raise NbiException("URL must contain at least 'topic/version/item'", HTTPStatus.METHOD_NOT_ALLOWED)

        reference = self.valid_methods
        for arg in args:
            if arg is None:
                break
            if not isinstance(reference, dict):
                raise NbiException("URL contains unexpected extra items '{}'".format(arg),
                                   HTTPStatus.METHOD_NOT_ALLOWED)

            if arg in reference:
                reference = reference[arg]
            elif "<ID>" in reference:
                reference = reference["<ID>"]
            elif "*" in reference:
                reference = reference["*"]
                break
            else:
                raise NbiException("Unexpected URL item {}".format(arg), HTTPStatus.METHOD_NOT_ALLOWED)
        if "TODO" in reference and method in reference["TODO"]:
            raise NbiException("Method {} not supported yet for this URL".format(method), HTTPStatus.NOT_IMPLEMENTED)
        elif "METHODS" in reference and method not in reference["METHODS"]:
            raise NbiException("Method {} not supported for this URL".format(method), HTTPStatus.METHOD_NOT_ALLOWED)
        return

    @staticmethod
    def _set_location_header(topic, version, item, id):
        """
        Insert response header Location with the URL of created item base on URL params
        :param topic:
        :param version:
        :param item:
        :param id:
        :return: None
        """
        # Use cherrypy.request.base for absoluted path and make use of request.header HOST just in case behind aNAT
        cherrypy.response.headers["Location"] = "/osm/{}/{}/{}/{}".format(topic, version, item, id)
        return

    @cherrypy.expose
    def default(self, topic=None, version=None, item=None, _id=None, item2=None, *args, **kwargs):
        session = None
        outdata = None
        _format = None
        method = "DONE"
        engine_item = None
        rollback = None
        try:
            if not topic or not version or not item:
                raise NbiException("URL must contain at least 'topic/version/item'", HTTPStatus.METHOD_NOT_ALLOWED)
            if topic not in ("admin", "vnfpkgm", "nsd", "nslcm"):
                raise NbiException("URL topic '{}' not supported".format(topic), HTTPStatus.METHOD_NOT_ALLOWED)
            if version != 'v1':
                raise NbiException("URL version '{}' not supported".format(version), HTTPStatus.METHOD_NOT_ALLOWED)

            if kwargs and "METHOD" in kwargs and kwargs["METHOD"] in ("PUT", "POST", "DELETE", "GET", "PATCH"):
                method = kwargs.pop("METHOD")
            else:
                method = cherrypy.request.method
            if kwargs and "FORCE" in kwargs:
                force = kwargs.pop("FORCE")
            else:
                force = False

            self._check_valid_url_method(method, topic, version, item, _id, item2, *args)

            if topic == "admin" and item == "tokens":
                return self.token(method, _id, kwargs)

            # self.engine.load_dbase(cherrypy.request.app.config)
            session = self._authorization()
            indata = self._format_in(kwargs)
            engine_item = item
            if item == "subscriptions":
                engine_item = topic + "_" + item
            if item2:
                engine_item = item2

            if topic == "nsd":
                engine_item = "nsds"
            elif topic == "vnfpkgm":
                engine_item = "vnfds"
            elif topic == "nslcm":
                engine_item = "nsrs"
                if item == "ns_lcm_op_occs":
                    engine_item = "nslcmops"
                if item == "vnfrs":
                    engine_item = "vnfrs"
            if engine_item == "vims":   # TODO this is for backward compatibility, it will remove in the future
                engine_item = "vim_accounts"

            if method == "GET":
                if item2 in ("nsd_content", "package_content", "artifacts", "vnfd", "nsd"):
                    if item2 in ("vnfd", "nsd"):
                        path = "$DESCRIPTOR"
                    elif args:
                        path = args
                    elif item2 == "artifacts":
                        path = ()
                    else:
                        path = None
                    file, _format = self.engine.get_file(session, engine_item, _id, path,
                                                         cherrypy.request.headers.get("Accept"))
                    outdata = file
                elif not _id:
                    outdata = self.engine.get_item_list(session, engine_item, kwargs)
                else:
                    outdata = self.engine.get_item(session, engine_item, _id)
            elif method == "POST":
                if item in ("ns_descriptors_content", "vnf_packages_content"):
                    _id = cherrypy.request.headers.get("Transaction-Id")
                    if not _id:
                        _id = self.engine.new_item(session, engine_item, {}, None, cherrypy.request.headers,
                                                   force=force)
                        rollback = {"session": session, "item": engine_item, "_id": _id, "force": True}
                    completed = self.engine.upload_content(session, engine_item, _id, indata, kwargs,
                                                           cherrypy.request.headers)
                    if completed:
                        self._set_location_header(topic, version, item, _id)
                    else:
                        cherrypy.response.headers["Transaction-Id"] = _id
                    outdata = {"id": _id}
                elif item == "ns_instances_content":
                    _id = self.engine.new_item(session, engine_item, indata, kwargs, force=force)
                    rollback = {"session": session, "item": engine_item, "_id": _id, "force": True}
                    self.engine.ns_operation(session, _id, "instantiate", {}, None)
                    self._set_location_header(topic, version, item, _id)
                    outdata = {"id": _id}
                elif item == "ns_instances" and item2:
                    _id = self.engine.ns_operation(session, _id, item2, indata, kwargs)
                    self._set_location_header(topic, version, "ns_lcm_op_occs", _id)
                    outdata = {"id": _id}
                    cherrypy.response.status = HTTPStatus.ACCEPTED.value
                else:
                    _id = self.engine.new_item(session, engine_item, indata, kwargs, cherrypy.request.headers,
                                               force=force)
                    self._set_location_header(topic, version, item, _id)
                    outdata = {"id": _id}
                    # TODO form NsdInfo when item in ("ns_descriptors", "vnf_packages")
                cherrypy.response.status = HTTPStatus.CREATED.value

            elif method == "DELETE":
                if not _id:
                    outdata = self.engine.del_item_list(session, engine_item, kwargs)
                    cherrypy.response.status = HTTPStatus.OK.value
                else:  # len(args) > 1
                    if item == "ns_instances_content":
                        opp_id = self.engine.ns_operation(session, _id, "terminate", {"autoremove": True}, None)
                        outdata = {"_id": opp_id}
                        cherrypy.response.status = HTTPStatus.ACCEPTED.value
                    else:
                        self.engine.del_item(session, engine_item, _id, force)
                        cherrypy.response.status = HTTPStatus.NO_CONTENT.value
                if engine_item in ("vim_accounts", "sdns"):
                    cherrypy.response.status = HTTPStatus.ACCEPTED.value

            elif method in ("PUT", "PATCH"):
                if not indata and not kwargs:
                    raise NbiException("Nothing to update. Provide payload and/or query string",
                                       HTTPStatus.BAD_REQUEST)
                if item2 in ("nsd_content", "package_content") and method == "PUT":
                    completed = self.engine.upload_content(session, engine_item, _id, indata, kwargs,
                                                           cherrypy.request.headers)
                    if not completed:
                        cherrypy.response.headers["Transaction-Id"] = id
                    cherrypy.response.status = HTTPStatus.NO_CONTENT.value
                    outdata = None
                else:
                    outdata = {"id": self.engine.edit_item(session, engine_item, _id, indata, kwargs, force=force)}
            else:
                raise NbiException("Method {} not allowed".format(method), HTTPStatus.METHOD_NOT_ALLOWED)
            return self._format_out(outdata, session, _format)
        except (NbiException, EngineException, DbException, FsException, MsgException) as e:
            cherrypy.log("Exception {}".format(e))
            cherrypy.response.status = e.http_code.value
            if hasattr(outdata, "close"):  # is an open file
                outdata.close()
            if rollback:
                try:
                    self.engine.del_item(**rollback)
                except Exception as e2:
                    cherrypy.log("Rollback Exception {}: {}".format(rollback, e2))
            error_text = str(e)
            if isinstance(e, MsgException):
                error_text = "{} has been '{}' but other modules cannot be informed because an error on bus".format(
                    engine_item[:-1], method, error_text)
            problem_details = {
                "code": e.http_code.name,
                "status": e.http_code.value,
                "detail": str(e),
            }
            return self._format_out(problem_details, session)
            # raise cherrypy.HTTPError(e.http_code.value, str(e))


# def validate_password(realm, username, password):
#     cherrypy.log("realm "+ str(realm))
#     if username == "admin" and password == "admin":
#         return True
#     return False


def _start_service():
    """
    Callback function called when cherrypy.engine starts
    Override configuration with env variables
    Set database, storage, message configuration
    Init database with admin/admin user password
    """
    cherrypy.log.error("Starting osm_nbi")
    # update general cherrypy configuration
    update_dict = {}

    engine_config = cherrypy.tree.apps['/osm'].config
    for k, v in environ.items():
        if not k.startswith("OSMNBI_"):
            continue
        k1, _, k2 = k[7:].lower().partition("_")
        if not k2:
            continue
        try:
            # update static configuration
            if k == 'OSMNBI_STATIC_DIR':
                engine_config["/static"]['tools.staticdir.dir'] = v
                engine_config["/static"]['tools.staticdir.on'] = True
            elif k == 'OSMNBI_SOCKET_PORT' or k == 'OSMNBI_SERVER_PORT':
                update_dict['server.socket_port'] = int(v)
            elif k == 'OSMNBI_SOCKET_HOST' or k == 'OSMNBI_SERVER_HOST':
                update_dict['server.socket_host'] = v
            elif k1 in ("server", "test", "auth", "log"):
                update_dict[k1 + '.' + k2] = v
            elif k1 in ("message", "database", "storage"):
                # k2 = k2.replace('_', '.')
                if k2 == "port":
                    engine_config[k1][k2] = int(v)
                else:
                    engine_config[k1][k2] = v
        except ValueError as e:
            cherrypy.log.error("Ignoring environ '{}': " + str(e))
        except Exception as e:
            cherrypy.log.warn("skipping environ '{}' on exception '{}'".format(k, e))

    if update_dict:
        cherrypy.config.update(update_dict)
        engine_config["global"].update(update_dict)

    # logging cherrypy
    log_format_simple = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)s %(message)s"
    log_formatter_simple = logging.Formatter(log_format_simple, datefmt='%Y-%m-%dT%H:%M:%S')
    logger_server = logging.getLogger("cherrypy.error")
    logger_access = logging.getLogger("cherrypy.access")
    logger_cherry = logging.getLogger("cherrypy")
    logger_nbi = logging.getLogger("nbi")

    if "log.file" in engine_config["global"]:
        file_handler = logging.handlers.RotatingFileHandler(engine_config["global"]["log.file"],
                                                            maxBytes=100e6, backupCount=9, delay=0)
        file_handler.setFormatter(log_formatter_simple)
        logger_cherry.addHandler(file_handler)
        logger_nbi.addHandler(file_handler)
    else:
        for format_, logger in {"nbi.server": logger_server,
                                "nbi.access": logger_access,
                                "%(name)s %(filename)s:%(lineno)s": logger_nbi
                                }.items():
            log_format_cherry = "%(asctime)s %(levelname)s {} %(message)s".format(format_)
            log_formatter_cherry = logging.Formatter(log_format_cherry, datefmt='%Y-%m-%dT%H:%M:%S')
            str_handler = logging.StreamHandler()
            str_handler.setFormatter(log_formatter_cherry)
            logger.addHandler(str_handler)

    if engine_config["global"].get("log.level"):
        logger_cherry.setLevel(engine_config["global"]["log.level"])
        logger_nbi.setLevel(engine_config["global"]["log.level"])

    # logging other modules
    for k1, logname in {"message": "nbi.msg", "database": "nbi.db", "storage": "nbi.fs"}.items():
        engine_config[k1]["logger_name"] = logname
        logger_module = logging.getLogger(logname)
        if "logfile" in engine_config[k1]:
            file_handler = logging.handlers.RotatingFileHandler(engine_config[k1]["logfile"],
                                                                maxBytes=100e6, backupCount=9, delay=0)
            file_handler.setFormatter(log_formatter_simple)
            logger_module.addHandler(file_handler)
        if "loglevel" in engine_config[k1]:
            logger_module.setLevel(engine_config[k1]["loglevel"])
    # TODO add more entries, e.g.: storage
    cherrypy.tree.apps['/osm'].root.engine.start(engine_config)
    try:
        cherrypy.tree.apps['/osm'].root.engine.init_db(target_version=database_version)
    except EngineException:
        pass
    # getenv('OSMOPENMANO_TENANT', None)


def _stop_service():
    """
    Callback function called when cherrypy.engine stops
    TODO: Ending database connections.
    """
    cherrypy.tree.apps['/osm'].root.engine.stop()
    cherrypy.log.error("Stopping osm_nbi")


def nbi(config_file):
    # conf = {
    #     '/': {
    #         #'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
    #         'tools.sessions.on': True,
    #         'tools.response_headers.on': True,
    #         # 'tools.response_headers.headers': [('Content-Type', 'text/plain')],
    #     }
    # }
    # cherrypy.Server.ssl_module = 'builtin'
    # cherrypy.Server.ssl_certificate = "http/cert.pem"
    # cherrypy.Server.ssl_private_key = "http/privkey.pem"
    # cherrypy.Server.thread_pool = 10
    # cherrypy.config.update({'Server.socket_port': config["port"], 'Server.socket_host': config["host"]})

    # cherrypy.config.update({'tools.auth_basic.on': True,
    #    'tools.auth_basic.realm': 'localhost',
    #    'tools.auth_basic.checkpassword': validate_password})
    cherrypy.engine.subscribe('start', _start_service)
    cherrypy.engine.subscribe('stop', _stop_service)
    cherrypy.quickstart(Server(), '/osm', config_file)


def usage():
    print("""Usage: {} [options]
        -c|--config [configuration_file]: loads the configuration file (default: ./nbi.cfg)
        -h|--help: shows this help
        """.format(sys.argv[0]))
    # --log-socket-host HOST: send logs to this host")
    # --log-socket-port PORT: send logs using this port (default: 9022)")


if __name__ == '__main__':
    try:
        # load parameters and configuration
        opts, args = getopt.getopt(sys.argv[1:], "hvc:", ["config=", "help"])
        # TODO add  "log-socket-host=", "log-socket-port=", "log-file="
        config_file = None
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("-c", "--config"):
                config_file = a
            # elif o == "--log-socket-port":
            #     log_socket_port = a
            # elif o == "--log-socket-host":
            #     log_socket_host = a
            # elif o == "--log-file":
            #     log_file = a
            else:
                assert False, "Unhandled option"
        if config_file:
            if not path.isfile(config_file):
                print("configuration file '{}' that not exist".format(config_file), file=sys.stderr)
                exit(1)
        else:
            for config_file in (__file__[:__file__.rfind(".")] + ".cfg", "./nbi.cfg", "/etc/osm/nbi.cfg"):
                if path.isfile(config_file):
                    break
            else:
                print("No configuration file 'nbi.cfg' found neither at local folder nor at /etc/osm/", file=sys.stderr)
                exit(1)
        nbi(config_file)
    except getopt.GetoptError as e:
        print(str(e), file=sys.stderr)
        # usage()
        exit(1)
