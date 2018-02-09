# -*- coding: utf-8 -*-

import dbmongo
import dbmemory
import fslocal
import msglocal
import msgkafka
import tarfile
import yaml
import json
import logging
from random import choice as random_choice
from uuid import uuid4
from hashlib import sha256, md5
from dbbase import DbException
from fsbase import FsException
from msgbase import MsgException
from http import HTTPStatus
from time import time
from copy import deepcopy

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class EngineException(Exception):

    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        Exception.__init__(self, message)


class Engine(object):

    def __init__(self):
        self.tokens = {}
        self.db = None
        self.fs = None
        self.msg = None
        self.config = None
        self.logger = logging.getLogger("nbi.engine")

    def start(self, config):
        """
        Connect to database, filesystem storage, and messaging
        :param config: two level dictionary with configuration. Top level should contain 'database', 'storage',
        :return: None
        """
        self.config = config
        try:
            if not self.db:
                if config["database"]["driver"] == "mongo":
                    self.db = dbmongo.DbMongo()
                    self.db.db_connect(config["database"])
                elif config["database"]["driver"] == "memory":
                    self.db = dbmemory.DbMemory()
                    self.db.db_connect(config["database"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[database]':'driver'".format(
                        config["database"]["driver"]))
            if not self.fs:
                if config["storage"]["driver"] == "local":
                    self.fs = fslocal.FsLocal()
                    self.fs.fs_connect(config["storage"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[storage]':'driver'".format(
                        config["storage"]["driver"]))
            if not self.msg:
                if config["message"]["driver"] == "local":
                    self.msg = msglocal.MsgLocal()
                    self.msg.connect(config["message"])
                elif config["message"]["driver"] == "kafka":
                    self.msg = msgkafka.MsgKafka()
                    self.msg.connect(config["message"])
                else:
                    raise EngineException("Invalid configuration param '{}' at '[message]':'driver'".format(
                        config["storage"]["driver"]))
        except (DbException, FsException, MsgException) as e:
            raise EngineException(str(e), http_code=e.http_code)

    def stop(self):
        try:
            if self.db:
                self.db.db_disconnect()
            if self.fs:
                self.fs.fs_disconnect()
            if self.fs:
                self.fs.fs_disconnect()
        except (DbException, FsException, MsgException) as e:
            raise EngineException(str(e), http_code=e.http_code)

    def authorize(self, token):
        try:
            if not token:
                raise EngineException("Needed a token or Authorization http header",
                                      http_code=HTTPStatus.UNAUTHORIZED)
            if token not in self.tokens:
                raise EngineException("Invalid token or Authorization http header",
                                      http_code=HTTPStatus.UNAUTHORIZED)
            session = self.tokens[token]
            now = time()
            if session["expires"] < now:
                del self.tokens[token]
                raise EngineException("Expired Token or Authorization http header",
                                      http_code=HTTPStatus.UNAUTHORIZED)
            return session
        except EngineException:
            if self.config["global"].get("test.user_not_authorized"):
                return {"id": "fake-token-id-for-test",
                        "project_id": self.config["global"].get("test.project_not_authorized", "admin"),
                        "username": self.config["global"]["test.user_not_authorized"]}
            else:
                raise

    def new_token(self, session, indata, remote):
        now = time()
        user_content = None

        # Try using username/password
        if indata.get("username"):
            user_rows = self.db.get_list("users", {"username": indata.get("username")})
            user_content = None
            if user_rows:
                user_content = user_rows[0]
                salt = user_content["_admin"]["salt"]
                shadow_password = sha256(indata.get("password", "").encode('utf-8') + salt.encode('utf-8')).hexdigest()
                if shadow_password != user_content["password"]:
                    user_content = None
            if not user_content:
                raise EngineException("Invalid username/password", http_code=HTTPStatus.UNAUTHORIZED)
        elif session:
            user_rows = self.db.get_list("users", {"username": session["username"]})
            if user_rows:
                user_content = user_rows[0]
            else:
                raise EngineException("Invalid token", http_code=HTTPStatus.UNAUTHORIZED)
        else:
            raise EngineException("Provide credentials: username/password or Authorization Bearer token",
                                  http_code=HTTPStatus.UNAUTHORIZED)

        token_id = ''.join(random_choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                           for _ in range(0, 32))
        if indata.get("project_id"):
            project_id = indata.get("project_id")
            if project_id not in user_content["projects"]:
                raise EngineException("project {} not allowed for this user".format(project_id),
                                      http_code=HTTPStatus.UNAUTHORIZED)
        else:
            project_id = user_content["projects"][0]
        if project_id == "admin":
            session_admin = True
        else:
            project = self.db.get_one("projects", {"_id": project_id})
            session_admin = project.get("admin", False)
        new_session = {"issued_at": now, "expires": now+3600,
                       "_id": token_id, "id": token_id, "project_id": project_id, "username": user_content["username"],
                       "remote_port": remote.port, "admin": session_admin}
        if remote.name:
            new_session["remote_host"] = remote.name
        elif remote.ip:
            new_session["remote_host"] = remote.ip

        self.tokens[token_id] = new_session
        return deepcopy(new_session)

    def get_token_list(self, session):
        token_list = []
        for token_id, token_value in self.tokens.items():
            if token_value["username"] == session["username"]:
                token_list.append(deepcopy(token_value))
        return token_list

    def get_token(self, session, token_id):
        token_value = self.tokens.get(token_id)
        if not token_value:
            raise EngineException("token not found", http_code=HTTPStatus.NOT_FOUND)
        if token_value["username"] != session["username"] and not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return token_value

    def del_token(self, token_id):
        try:
            del self.tokens[token_id]
            return "token '{}' deleted".format(token_id)
        except KeyError:
            raise EngineException("Token '{}' not found".format(token_id), http_code=HTTPStatus.NOT_FOUND)

    @staticmethod
    def _remove_envelop(item, indata=None):
        """
        Obtain the useful data removing the envelop. It goes throw the vnfd or nsd catalog and returns the
        vnfd or nsd content
        :param item: can be vnfds, nsds, users, projects,
        :param indata: Content to be inspected
        :return: the useful part of indata
        """
        clean_indata = indata
        if not indata:
            return {}
        if item == "vnfds":
            if clean_indata.get('vnfd:vnfd-catalog'):
                clean_indata = clean_indata['vnfd:vnfd-catalog']
            elif clean_indata.get('vnfd-catalog'):
                clean_indata = clean_indata['vnfd-catalog']
            if clean_indata.get('vnfd'):
                if not isinstance(clean_indata['vnfd'], list) or len(clean_indata['vnfd']) != 1:
                    raise EngineException("'vnfd' must be a list only one element")
                clean_indata = clean_indata['vnfd'][0]
        elif item == "nsds":
            if clean_indata.get('nsd:nsd-catalog'):
                clean_indata = clean_indata['nsd:nsd-catalog']
            elif clean_indata.get('nsd-catalog'):
                clean_indata = clean_indata['nsd-catalog']
            if clean_indata.get('nsd'):
                if not isinstance(clean_indata['nsd'], list) or len(clean_indata['nsd']) != 1:
                    raise EngineException("'nsd' must be a list only one element")
                clean_indata = clean_indata['nsd'][0]
        return clean_indata

    def _validate_new_data(self, session, item, indata):
        if item == "users":
            if not indata.get("username"):
                raise EngineException("missing 'username'", HTTPStatus.UNPROCESSABLE_ENTITY)
            if not indata.get("password"):
                raise EngineException("missing 'password'", HTTPStatus.UNPROCESSABLE_ENTITY)
            if not indata.get("projects"):
                raise EngineException("missing 'projects'", HTTPStatus.UNPROCESSABLE_ENTITY)
            # check username not exist
            if self.db.get_one(item, {"username": indata.get("username")}, fail_on_empty=False, fail_on_more=False):
                raise EngineException("username '{}' exist".format(indata["username"]), HTTPStatus.CONFLICT)
        elif item == "projects":
            if not indata.get("name"):
                raise EngineException("missing 'name'")
            # check name not exist
            if self.db.get_one(item, {"name": indata.get("name")}, fail_on_empty=False, fail_on_more=False):
                raise EngineException("name '{}' exist".format(indata["name"]), HTTPStatus.CONFLICT)
        elif item == "vnfds" or item == "nsds":
            filter = {"id": indata["id"]}
            # TODO add admin to filter, validate rights
            self._add_read_filter(session, item, filter)
            if self.db.get_one(item, filter, fail_on_empty=False):
                raise EngineException("{} with id '{}' already exist for this tenant".format(item[:-1], indata["id"]),
                                      HTTPStatus.CONFLICT)

            # TODO validate with pyangbind
        elif item == "nsrs":
            pass

    def _format_new_data(self, session, item, indata, admin=None):
        now = time()
        if not "_admin" in indata:
            indata["_admin"] = {}
        indata["_admin"]["created"] = now
        indata["_admin"]["modified"] = now
        if item == "users":
            _id = indata["username"]
            salt = uuid4().hex
            indata["_admin"]["salt"] =  salt
            indata["password"] = sha256(indata["password"].encode('utf-8') + salt.encode('utf-8')).hexdigest()
        elif item == "projects":
            _id = indata["name"]
        else:
            _id = None
            storage = None
            if admin:
                _id = admin.get("_id")
                storage = admin.get("storage")
            if not _id:
                _id = str(uuid4())
            if item == "vnfds" or item == "nsds":
                if not indata["_admin"].get("projects_read"):
                    indata["_admin"]["projects_read"] = [session["project_id"]]
                if not indata["_admin"].get("projects_write"):
                    indata["_admin"]["projects_write"] = [session["project_id"]]
            if storage:
                indata["_admin"]["storage"] = storage
        indata["_id"] = _id

    def _new_item_partial(self, session, item, indata, headers):
        """
        Used for recieve content by chunks (with a transaction_id header and/or gzip file. It will store and extract
        :param session: session
        :param item:
        :param indata: http body request
        :param headers:  http request headers
        :return: a dict with::
            _id: <transaction_id>
            storage: <path>:  where it is saving
            desc: <dict>: descriptor: Only present when all the content is received, extracted and read the descriptor
        """
        content_range_text = headers.get("Content-Range")
        transaction_id = headers.get("Transaction-Id")
        filename = headers.get("Content-Filename", "pkg")
        # TODO change to Content-Disposition filename https://tools.ietf.org/html/rfc6266
        expected_md5 = headers.get("Content-File-MD5")
        compressed = None
        if "application/gzip" in headers.get("Content-Type") or "application/x-gzip" in headers.get("Content-Type") or \
                "application/zip" in headers.get("Content-Type"):
            compressed = "gzip"
        file_pkg = None
        error_text = ""
        try:
            if content_range_text:
                content_range = content_range_text.replace("-", " ").replace("/", " ").split()
                if content_range[0] != "bytes":  # TODO check x<y not negative < total....
                    raise IndexError()
                start = int(content_range[1])
                end = int(content_range[2]) + 1
                total = int(content_range[3])
                if len(indata) != end-start:
                    raise EngineException("Mismatch between Content-Range header {}-{} and body length of {}".format(
                        start, end-1, len(indata)), HTTPStatus.BAD_REQUEST)
            else:
                start = 0
                total = end = len(indata)
            if not transaction_id:
                # generate transaction
                transaction_id = str(uuid4())
                self.fs.mkdir(transaction_id)
                # control_file = open(self.storage["path"] + transaction_id + "/.osm.yaml", 'wb')
                # control = {"received": 0}
            elif not self.fs.file_exists(transaction_id):
                raise EngineException("invalid Transaction-Id header", HTTPStatus.NOT_FOUND)
            else:
                pass
                # control_file = open(self.storage["path"] + transaction_id + "/.osm.yaml", 'rw')
                # control = yaml.load(control_file)
                # control_file.seek(0, 0)
            storage = self.fs.get_params()
            storage["folder"] = transaction_id
            storage["file"] = filename

            file_path = (transaction_id, filename)
            if self.fs.file_exists(file_path):
                file_size = self.fs.file_size(file_path)
            else:
                file_size = 0
            if file_size != start:
                raise EngineException("invalid upload transaction sequence, expected '{}' but received '{}'".format(
                    file_size, start), HTTPStatus.BAD_REQUEST)
            file_pkg = self.fs.file_open(file_path, 'a+b')
            file_pkg.write(indata)
            if end != total:
                return {"_id": transaction_id, "storage": storage}
            if expected_md5:
                file_pkg.seek(0, 0)
                file_md5 = md5()
                chunk_data = file_pkg.read(1024)
                while chunk_data:
                    file_md5.update(chunk_data)
                    chunk_data = file_pkg.read(1024)
                if expected_md5 != file_md5.hexdigest():
                    raise EngineException("Error, MD5 mismatch", HTTPStatus.CONFLICT)
            file_pkg.seek(0, 0)
            if compressed == "gzip":
                # TODO unzip,
                storage["tarfile"] = filename
                tar = tarfile.open(mode='r', fileobj=file_pkg)
                descriptor_file_name = None
                for tarinfo in tar:
                    tarname = tarinfo.name
                    tarname_path = tarname.split("/")
                    if not tarname_path[0] or ".." in tarname_path:  # if start with "/" means absolute path
                        raise EngineException("Absolute path or '..' are not allowed for package descriptor tar.gz")
                    if len(tarname_path) == 1 and not tarinfo.isdir():
                        raise EngineException("All files must be inside a dir for package descriptor tar.gz")
                    if tarname.endswith(".yaml") or tarname.endswith(".json") or tarname.endswith(".yml"):
                        storage["file"] = tarname_path[0]
                        if len(tarname_path) == 2:
                            if descriptor_file_name:
                                raise EngineException("Found more than one descriptor file at package descriptor tar.gz")
                            descriptor_file_name = tarname
                if not descriptor_file_name:
                    raise EngineException("Not found any descriptor file at package descriptor tar.gz")
                self.fs.file_extract(tar, transaction_id)
                with self.fs.file_open((transaction_id, descriptor_file_name), "r") as descriptor_file:
                    content = descriptor_file.read()
            else:
                content = file_pkg.read()
                tarname = ""

            if tarname.endswith(".json"):
                error_text = "Invalid json format "
                indata = json.load(content)
            else:
                error_text = "Invalid yaml format "
                indata = yaml.load(content)
            return {"_id": transaction_id, "storage": storage, "desc": indata}
        except EngineException:
            raise
        except IndexError:
            raise EngineException("invalid Content-Range header format. Expected 'bytes start-end/total'",
                                  HTTPStatus.BAD_REQUEST)
        except IOError as e:
            raise EngineException("invalid upload transaction sequence: '{}'".format(e), HTTPStatus.BAD_REQUEST)
        except (ValueError, yaml.YAMLError) as e:
            raise EngineException(error_text + str(e))
        finally:
            if file_pkg:
                file_pkg.close()

    def new_nsr(self, session, ns_request):
        """
        Creates a new nsr into database
        :param session: contains the used login username and working project
        :param ns_request: params to be used for the nsr
        :return: nsr descriptor to be stored at database and the _id
        """

        # look for nsr
        nsd = self.get_item(session, "nsds", ns_request["nsdId"])
        _id = str(uuid4())
        nsr_descriptor = {
            "name": ns_request["nsName"],
            "name-ref": ns_request["nsName"],
            "short-name": ns_request["nsName"],
            "admin-status": "ENABLED",
            "nsd": nsd,
            "datacenter": ns_request["vimAccountId"],
            "resource-orchestrator": "osmopenmano",
            "description": ns_request.get("nsDescription", ""),
            "constituent-vnfr-ref": ["TODO datacenter-id, vnfr-id"],

            "operational-status": "init",    #  typedef ns-operational-
            "config-status": "init",         #  typedef config-states
            "detailed-status": "scheduled",

            "orchestration-progress": {},  # {"networks": {"active": 0, "total": 0}, "vms": {"active": 0, "total": 0}},

            "crete-time": time(),
            "nsd-name-ref": nsd["name"],
            "operational-events": [],   # "id", "timestamp", "description", "event",
            "nsd-ref": nsd["id"],
            "ns-instance-config-ref": _id,
            "id": _id,

            # "input-parameter": xpath, value,
            "ssh-authorized-key": ns_request.get("key-pair-ref"),
        }
        ns_request["nsr_id"] = _id
        return nsr_descriptor, _id

    def new_item(self, session, item, indata={}, kwargs=None, headers={}):
        """
        Creates a new entry into database
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id, transaction_id: identity of the inserted data. or transaction_id if Content-Range is used
        """
        # TODO validate input. Check not exist at database
        # TODO add admin and status

        transaction = None
        if headers.get("Content-Range") or "application/gzip" in headers.get("Content-Type") or \
            "application/x-gzip" in headers.get("Content-Type") or "application/zip" in headers.get("Content-Type"):
            if not indata:
                raise EngineException("Empty payload")
            transaction = self._new_item_partial(session, item, indata, headers)
            if "desc" not in transaction:
                return transaction["_id"], False
            indata = transaction["desc"]

        content = self._remove_envelop(item, indata)

        # Override descriptor with query string kwargs
        if kwargs:
            try:
                for k, v in kwargs.items():
                    update_content = content
                    kitem_old = None
                    klist = k.split(".")
                    for kitem in klist:
                        if kitem_old is not None:
                            update_content = update_content[kitem_old]
                        if isinstance(update_content, dict):
                            kitem_old = kitem
                        elif isinstance(update_content, list):
                            kitem_old = int(kitem)
                        else:
                            raise EngineException(
                                "Invalid query string '{}'. Descriptor is not a list nor dict at '{}'".format(k, kitem))
                    update_content[kitem_old] = v
            except KeyError:
                raise EngineException(
                    "Invalid query string '{}'. Descriptor does not contain '{}'".format(k, kitem_old))
            except ValueError:
                raise EngineException("Invalid query string '{}'. Expected integer index list instead of '{}'".format(
                    k, kitem))
            except IndexError:
                raise EngineException(
                    "Invalid query string '{}'. Index '{}' out of  range".format(k, kitem_old))
        if not indata:
            raise EngineException("Empty payload")

        if item == "nsrs":
            # in this case the imput descriptor is not the data to be stored
            ns_request = content
            content, _id = self.new_nsr(session, ns_request)
            transaction = {"_id": _id}

        self._validate_new_data(session, item, content)
        self._format_new_data(session, item, content, transaction)
        _id = self.db.create(item, content)
        if item == "nsrs":
            self.msg.write("ns", "create", _id)
        return _id, True

    def _add_read_filter(self, session, item, filter):
        if session["project_id"] == "admin":  # allows all
            return filter
        if item == "users":
            filter["username"] = session["username"]
        elif item == "vnfds" or item == "nsds":
            filter["_admin.projects_read.cont"] = ["ANY", session["project_id"]]

    def _add_delete_filter(self, session, item, filter):
        if session["project_id"] != "admin" and item in ("users", "projects"):
            raise EngineException("Only admin users can perform this task", http_code=HTTPStatus.FORBIDDEN)
        if item == "users":
            if filter.get("_id") == session["username"] or filter.get("username") == session["username"]:
                raise EngineException("You cannot delete your own user", http_code=HTTPStatus.CONFLICT)
        elif item == "project":
            if filter.get("_id") == session["project_id"]:
                raise EngineException("You cannot delete your own project", http_code=HTTPStatus.CONFLICT)
        elif item in ("vnfds", "nsds") and session["project_id"] != "admin":
            filter["_admin.projects_write.cont"] = ["ANY", session["project_id"]]

    def get_item_list(self, session, item, filter={}):
        """
        Get a list of items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param filter: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        # TODO add admin to filter, validate rights
        self._add_read_filter(session, item, filter)
        return self.db.get_list(item, filter)

    def get_item(self, session, item, _id):
        """
        Get complete information on an items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param _id: server id of the item
        :return: dictionary, raise exception if not found.
        """
        filter = {"_id": _id}
        # TODO add admin to filter, validate rights
        self._add_read_filter(session, item, filter)
        return self.db.get_one(item, filter)

    def del_item_list(self, session, item, filter={}):
        """
        Delete a list of items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param filter: filter of data to be applied
        :return: The deleted list, it can be empty if no one match the filter.
        """
        # TODO add admin to filter, validate rights
        self._add_read_filter(session, item, filter)
        return self.db.del_list(item, filter)

    def del_item(self, session, item, _id):
        """
        Get complete information on an items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param _id: server id of the item
        :return: dictionary, raise exception if not found.
        """
        # TODO add admin to filter, validate rights
        # data = self.get_item(item, _id)
        filter = {"_id": _id}
        self._add_delete_filter(session, item, filter)

        if item == "nsrs":
            desc = self.db.get_one(item, filter)
            desc["_admin"]["to_delete"] = True
            self.db.replace(item, _id, desc)   # TODO change to set_one
            self.msg.write("ns", "delete", _id)
            return {"deleted": 1}

        v = self.db.del_one(item, filter)
        self.fs.file_delete(_id, ignore_non_exist=True)
        if item == "nsrs":
            self.msg.write("ns", "delete", _id)
        return v

    def prune(self):
        """
        Prune database not needed content
        :return: None
        """
        return self.db.del_list("nsrs", {"_admin.to_delete": True})

    def create_admin(self):
        """
        Creates a new user admin/admin into database. Only allowed if database is empty. Useful for initialization
        :return: _id identity of the inserted data.
        """
        users = self.db.get_one("users", fail_on_empty=False, fail_on_more=False)
        if users:
            raise EngineException("Unauthorized. Database users is not empty", HTTPStatus.UNAUTHORIZED)
        indata = {"username": "admin", "password": "admin", "projects": ["admin"]}
        fake_session = {"project_id": "admin", "username": "admin"}
        self._format_new_data(fake_session, "users", indata)
        _id = self.db.create("users", indata)
        return _id

    def edit_item(self, session, item, id, indata={}, kwargs=None):
        """
        Update an existing entry at database
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param id: identity of entry to be updated
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :return: dictionary, raise exception if not found.
        """

        content = self.get_item(session, item, id)
        if indata:
            indata = self._remove_envelop(item, indata)
            # TODO update content with with a deep-update

        # Override descriptor with query string kwargs
        if kwargs:
            try:
                for k, v in kwargs.items():
                    update_content = content
                    kitem_old = None
                    klist = k.split(".")
                    for kitem in klist:
                        if kitem_old is not None:
                            update_content = update_content[kitem_old]
                        if isinstance(update_content, dict):
                            kitem_old = kitem
                        elif isinstance(update_content, list):
                            kitem_old = int(kitem)
                        else:
                            raise EngineException(
                                "Invalid query string '{}'. Descriptor is not a list nor dict at '{}'".format(k, kitem))
                    update_content[kitem_old] = v
            except KeyError:
                raise EngineException(
                    "Invalid query string '{}'. Descriptor does not contain '{}'".format(k, kitem_old))
            except ValueError:
                raise EngineException("Invalid query string '{}'. Expected integer index list instead of '{}'".format(
                    k, kitem))
            except IndexError:
                raise EngineException(
                    "Invalid query string '{}'. Index '{}' out of  range".format(k, kitem_old))

        self._validate_new_data(session, item, content)
        # self._format_new_data(session, item, content)
        self.db.replace(item, id, content)
        return id


