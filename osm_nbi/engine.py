# -*- coding: utf-8 -*-

from osm_common import dbmongo
from osm_common import dbmemory
from osm_common import fslocal
from osm_common import msglocal
from osm_common import msgkafka
import tarfile
import yaml
import json
import logging
from random import choice as random_choice
from uuid import uuid4
from hashlib import sha256, md5
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus
from time import time
from copy import deepcopy
from validation import validate_input, ValidationError

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class EngineException(Exception):

    def __init__(self, message, http_code=HTTPStatus.BAD_REQUEST):
        self.http_code = http_code
        Exception.__init__(self, message)


def _deep_update(dict_to_change, dict_reference):
    """
    Modifies one dictionary with the information of the other following https://tools.ietf.org/html/rfc7396
    :param dict_to_change:  Ends modified
    :param dict_reference: reference
    :return: none
    """
    for k in dict_reference:
        if dict_reference[k] is None:   # None->Anything
            if k in dict_to_change:
                del dict_to_change[k]
        elif not isinstance(dict_reference[k], dict):  # NotDict->Anything
            dict_to_change[k] = dict_reference[k]
        elif k not in dict_to_change:  # Dict->Empty
            dict_to_change[k] = deepcopy(dict_reference[k])
            _deep_update(dict_to_change[k], dict_reference[k])
        elif isinstance(dict_to_change[k], dict):  # Dict->Dict
            _deep_update(dict_to_change[k], dict_reference[k])
        else:       # Dict->NotDict
            dict_to_change[k] = deepcopy(dict_reference[k])
            _deep_update(dict_to_change[k], dict_reference[k])


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
        :param item: can be vnfds, nsds, users, projects, userDefinedData (initial content of a vnfds, nsds
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
        elif item == "userDefinedData":
            if "userDefinedData" in indata:
                clean_indata = clean_indata['userDefinedData']
        return clean_indata

    def _check_dependencies_on_descriptor(self, session, item, descriptor_id):
        """
        Check that the descriptor to be deleded is not a dependency of others
        :param session: client session information
        :param item: can be vnfds, nsds
        :param descriptor_id: id of descriptor to be deleted
        :return: None or raises exception
        """
        if item == "vnfds":
            _filter = {"constituent-vnfd.ANYINDEX.vnfd-id-ref": descriptor_id}
            if self.get_item_list(session, "nsds", _filter):
                raise EngineException("There are nsd that depends on this VNFD", http_code=HTTPStatus.CONFLICT)
        elif item == "nsds":
            _filter = {"nsdId": descriptor_id}
            if self.get_item_list(session, "nsrs", _filter):
                raise EngineException("There are nsr that depends on this NSD", http_code=HTTPStatus.CONFLICT)

    def _check_descriptor_dependencies(self, session, item, descriptor):
        """
        Check that the dependent descriptors exist on a new descriptor or edition
        :param session: client session information
        :param item: can be nsds, nsrs
        :param descriptor: descriptor to be inserted or edit
        :return: None or raises exception
        """
        if item == "nsds":
            if not descriptor.get("constituent-vnfd"):
                return
            for vnf in descriptor["constituent-vnfd"]:
                vnfd_id = vnf["vnfd-id-ref"]
                if not self.get_item_list(session, "vnfds", {"id": vnfd_id}):
                    raise EngineException("Descriptor error at 'constituent-vnfd':'vnfd-id-ref'='{}' references a non "
                                          "existing vnfd".format(vnfd_id), http_code=HTTPStatus.CONFLICT)
        elif item == "nsrs":
            if not descriptor.get("nsdId"):
                return
            nsd_id = descriptor["nsdId"]
            if not self.get_item_list(session, "nsds", {"id": nsd_id}):
                raise EngineException("Descriptor error at nsdId='{}' references a non exist nsd".format(nsd_id),
                                      http_code=HTTPStatus.CONFLICT)

    def _validate_new_data(self, session, item, indata, id=None, force=False):
        if item == "users":
            if not indata.get("username"):
                raise EngineException("missing 'username'", HTTPStatus.UNPROCESSABLE_ENTITY)
            if not indata.get("password"):
                raise EngineException("missing 'password'", HTTPStatus.UNPROCESSABLE_ENTITY)
            if not indata.get("projects"):
                raise EngineException("missing 'projects'", HTTPStatus.UNPROCESSABLE_ENTITY)
            # check username not exists
            if self.db.get_one(item, {"username": indata.get("username")}, fail_on_empty=False, fail_on_more=False):
                raise EngineException("username '{}' exists".format(indata["username"]), HTTPStatus.CONFLICT)
        elif item == "projects":
            if not indata.get("name"):
                raise EngineException("missing 'name'")
            # check name not exists
            if self.db.get_one(item, {"name": indata.get("name")}, fail_on_empty=False, fail_on_more=False):
                raise EngineException("name '{}' exists".format(indata["name"]), HTTPStatus.CONFLICT)
        elif item in ("vnfds", "nsds"):
            filter = {"id": indata["id"]}
            if id:
                filter["_id.neq"] = id
            # TODO add admin to filter, validate rights
            self._add_read_filter(session, item, filter)
            if self.db.get_one(item, filter, fail_on_empty=False):
                raise EngineException("{} with id '{}' already exists for this tenant".format(item[:-1], indata["id"]),
                                      HTTPStatus.CONFLICT)

            # TODO validate with pyangbind
            if item == "nsds" and not force:
                self._check_descriptor_dependencies(session, "nsds", indata)
        elif item == "userDefinedData":
            # TODO validate userDefinedData is a keypair values
            pass

        elif item == "nsrs":
            pass
        elif item == "vim_accounts" or item == "sdns":
            filter = {"name": indata.get("name")}
            if id:
                filter["_id.neq"] = id
            if self.db.get_one(item, filter, fail_on_empty=False, fail_on_more=False):
                raise EngineException("name '{}' already exists for {}".format(indata["name"], item),
                                      HTTPStatus.CONFLICT)

    def _check_ns_operation(self, session, nsr, operation, indata):
        """
        Check that user has enter right parameters for the operation
        :param session:
        :param operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param indata: descriptor with the parameters of the operation
        :return: None
        """
        if operation == "action":
            if indata.get("vnf_member_index"):
                indata["member_vnf_index"] = indata.pop("vnf_member_index")    # for backward compatibility
            for vnf in nsr["nsd"]["constituent-vnfd"]:
                if indata["member_vnf_index"] == vnf["member-vnf-index"]:
                    # TODO get vnfd, check primitives
                    break
            else:
                raise EngineException("Invalid parameter member_vnf_index='{}' is not one of the nsd "
                                      "constituent-vnfd".format(indata["member_vnf_index"]))

    def _format_new_data(self, session, item, indata):
        now = time()
        if "_admin" not in indata:
            indata["_admin"] = {}
        indata["_admin"]["created"] = now
        indata["_admin"]["modified"] = now
        if item == "users":
            indata["_id"] = indata["username"]
            salt = uuid4().hex
            indata["_admin"]["salt"] = salt
            indata["password"] = sha256(indata["password"].encode('utf-8') + salt.encode('utf-8')).hexdigest()
        elif item == "projects":
            indata["_id"] = indata["name"]
        else:
            if not indata.get("_id"):
                indata["_id"] = str(uuid4())
            if item in ("vnfds", "nsds", "nsrs", "vnfrs"):
                if not indata["_admin"].get("projects_read"):
                    indata["_admin"]["projects_read"] = [session["project_id"]]
                if not indata["_admin"].get("projects_write"):
                    indata["_admin"]["projects_write"] = [session["project_id"]]
                if item == "nsds":
                    # transform constituent-vnfd:member-vnf-index to string
                    if indata.get("constituent-vnfd"):
                        for constituent_vnfd in indata["constituent-vnfd"]:
                            if "member-vnf-index" in constituent_vnfd:
                                constituent_vnfd["member-vnf-index"] = str(constituent_vnfd["member-vnf-index"])
            if item in ("vnfds", "nsds"):
                indata["_admin"]["onboardingState"] = "CREATED"
                indata["_admin"]["operationalState"] = "DISABLED"
                indata["_admin"]["usageSate"] = "NOT_IN_USE"
            if item == "nsrs":
                indata["_admin"]["nsState"] = "NOT_INSTANTIATED"
            if item in ("vim_accounts", "sdns"):
                indata["_admin"]["operationalState"] = "PROCESSING"

    def upload_content(self, session, item, _id, indata, kwargs, headers):
        """
        Used for receiving content by chunks (with a transaction_id header and/or gzip file. It will store and extract)
        :param session: session
        :param item: can be nsds or vnfds
        :param _id : the nsd,vnfd is already created, this is the id
        :param indata: http body request
        :param kwargs: user query string to override parameters. NOT USED
        :param headers:  http request headers
        :return: True package has is completely uploaded or False if partial content has been uplodaed.
            Raise exception on error
        """
        # Check that _id exists and it is valid
        current_desc = self.get_item(session, item, _id)

        content_range_text = headers.get("Content-Range")
        expected_md5 = headers.get("Content-File-MD5")
        compressed = None
        content_type = headers.get("Content-Type")
        if content_type and "application/gzip" in content_type or "application/x-gzip" in content_type or \
                "application/zip" in content_type:
            compressed = "gzip"
        filename = headers.get("Content-Filename")
        if not filename:
            filename = "package.tar.gz" if compressed else "package"
        # TODO change to Content-Disposition filename https://tools.ietf.org/html/rfc6266
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
            else:
                start = 0

            if start:
                if not self.fs.file_exists(_id, 'dir'):
                    raise EngineException("invalid Transaction-Id header", HTTPStatus.NOT_FOUND)
            else:
                self.fs.file_delete(_id, ignore_non_exist=True)
                self.fs.mkdir(_id)

            storage = self.fs.get_params()
            storage["folder"] = _id

            file_path = (_id, filename)
            if self.fs.file_exists(file_path, 'file'):
                file_size = self.fs.file_size(file_path)
            else:
                file_size = 0
            if file_size != start:
                raise EngineException("invalid Content-Range start sequence, expected '{}' but received '{}'".format(
                    file_size, start), HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
            file_pkg = self.fs.file_open(file_path, 'a+b')
            if isinstance(indata, dict):
                indata_text = yaml.safe_dump(indata, indent=4, default_flow_style=False)
                file_pkg.write(indata_text.encode(encoding="utf-8"))
            else:
                indata_len = 0
                while True:
                    indata_text = indata.read(4096)
                    indata_len += len(indata_text)
                    if not indata_text:
                        break
                    file_pkg.write(indata_text)
            if content_range_text:
                if indata_len != end-start:
                    raise EngineException("Mismatch between Content-Range header {}-{} and body length of {}".format(
                        start, end-1, indata_len), HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                if end != total:
                    # TODO update to UPLOADING
                    return False

            # PACKAGE UPLOADED
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
                        storage["pkg-dir"] = tarname_path[0]
                        if len(tarname_path) == 2:
                            if descriptor_file_name:
                                raise EngineException(
                                    "Found more than one descriptor file at package descriptor tar.gz")
                            descriptor_file_name = tarname
                if not descriptor_file_name:
                    raise EngineException("Not found any descriptor file at package descriptor tar.gz")
                storage["descriptor"] = descriptor_file_name
                storage["zipfile"] = filename
                self.fs.file_extract(tar, _id)
                with self.fs.file_open((_id, descriptor_file_name), "r") as descriptor_file:
                    content = descriptor_file.read()
            else:
                content = file_pkg.read()
                storage["descriptor"] = descriptor_file_name = filename

            if descriptor_file_name.endswith(".json"):
                error_text = "Invalid json format "
                indata = json.load(content)
            else:
                error_text = "Invalid yaml format "
                indata = yaml.load(content)

            current_desc["_admin"]["storage"] = storage
            current_desc["_admin"]["onboardingState"] = "ONBOARDED"
            current_desc["_admin"]["operationalState"] = "ENABLED"

            self._edit_item(session, item, _id, current_desc, indata, kwargs)
            # TODO if descriptor has changed because kwargs update content and remove cached zip
            # TODO if zip is not present creates one
            return True

        except EngineException:
            raise
        except IndexError:
            raise EngineException("invalid Content-Range header format. Expected 'bytes start-end/total'",
                                  HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
        except IOError as e:
            raise EngineException("invalid upload transaction sequence: '{}'".format(e), HTTPStatus.BAD_REQUEST)
        except tarfile.ReadError as e:
            raise EngineException("invalid file content {}".format(e), HTTPStatus.BAD_REQUEST)
        except (ValueError, yaml.YAMLError) as e:
            raise EngineException(error_text + str(e))
        finally:
            if file_pkg:
                file_pkg.close()

    def new_nsr(self, session, ns_request):
        """
        Creates a new nsr into database. It also creates needed vnfrs
        :param session: contains the used login username and working project
        :param ns_request: params to be used for the nsr
        :return: the _id of nsr descriptor stored at database
        """
        rollback = []
        step = ""
        try:
            # look for nsr
            step = "getting nsd id='{}' from database".format(ns_request.get("nsdId"))
            nsd = self.get_item(session, "nsds", ns_request["nsdId"])
            nsr_id = str(uuid4())
            now = time()
            step = "filling nsr from input data"
            nsr_descriptor = {
                "name": ns_request["nsName"],
                "name-ref": ns_request["nsName"],
                "short-name": ns_request["nsName"],
                "admin-status": "ENABLED",
                "nsd": nsd,
                "datacenter": ns_request["vimAccountId"],
                "resource-orchestrator": "osmopenmano",
                "description": ns_request.get("nsDescription", ""),
                "constituent-vnfr-ref": [],

                "operational-status": "init",    # typedef ns-operational-
                "config-status": "init",         # typedef config-states
                "detailed-status": "scheduled",

                "orchestration-progress": {},
                # {"networks": {"active": 0, "total": 0}, "vms": {"active": 0, "total": 0}},

                "crete-time": now,
                "nsd-name-ref": nsd["name"],
                "operational-events": [],   # "id", "timestamp", "description", "event",
                "nsd-ref": nsd["id"],
                "instantiate_params": ns_request,
                "ns-instance-config-ref": nsr_id,
                "id": nsr_id,
                "_id": nsr_id,
                # "input-parameter": xpath, value,
                "ssh-authorized-key": ns_request.get("key-pair-ref"),
            }
            ns_request["nsr_id"] = nsr_id

            # Create VNFR
            needed_vnfds = {}
            for member_vnf in nsd["constituent-vnfd"]:
                vnfd_id = member_vnf["vnfd-id-ref"]
                step = "getting vnfd id='{}' constituent-vnfd='{}' from database".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])
                if vnfd_id not in needed_vnfds:
                    # Obtain vnfd
                    vnf_filter = {"id": vnfd_id}
                    self._add_read_filter(session, "vnfds", vnf_filter)
                    vnfd = self.db.get_one("vnfds", vnf_filter)
                    vnfd.pop("_admin")
                    needed_vnfds[vnfd_id] = vnfd
                else:
                    vnfd = needed_vnfds[vnfd_id]
                step = "filling vnfr  vnfd-id='{}' constituent-vnfd='{}'".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])
                vnfr_id = str(uuid4())
                vnfr_descriptor = {
                    "id": vnfr_id,
                    "_id": vnfr_id,
                    "nsr-id-ref": nsr_id,
                    "member-vnf-index-ref": member_vnf["member-vnf-index"],
                    "created-time": now,
                    # "vnfd": vnfd,        # at OSM model.but removed to avoid data duplication TODO: revise
                    "vnfd-ref": vnfd_id,
                    "vnfd-id": vnfr_id,    # not at OSM model, but useful
                    "vim-account-id": None,
                    "vdur": [],
                    "connection-point": [],
                    "ip-address": None,  # mgmt-interface filled by LCM
                }
                for cp in vnfd.get("connection-point", ()):
                    vnf_cp = {
                        "name": cp["name"],
                        "connection-point-id": cp.get("id"),
                        "id": cp.get("id"),
                        # "ip-address", "mac-address" # filled by LCM
                        # vim-id  # TODO it would be nice having a vim port id
                    }
                    vnfr_descriptor["connection-point"].append(vnf_cp)
                for vdu in vnfd["vdu"]:
                    vdur_id = str(uuid4())
                    vdur = {
                        "id": vdur_id,
                        "vdu-id-ref": vdu["id"],
                        "ip-address": None,  # mgmt-interface filled by LCM
                        # "vim-id", "flavor-id", "image-id", "management-ip" # filled by LCM
                        "internal-connection-point": [],
                    }
                    # TODO volumes: name, volume-id
                    for icp in vdu.get("internal-connection-point", ()):
                        vdu_icp = {
                            "id": icp["id"],
                            "connection-point-id": icp["id"],
                            "name": icp.get("name"),
                            # "ip-address", "mac-address" # filled by LCM
                            # vim-id  # TODO it would be nice having a vim port id
                        }
                        vdur["internal-connection-point"].append(vdu_icp)
                    vnfr_descriptor["vdur"].append(vdur)

                step = "creating vnfr vnfd-id='{}' constituent-vnfd='{}' at database".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])
                self._format_new_data(session, "vnfrs", vnfr_descriptor)
                self.db.create("vnfrs", vnfr_descriptor)
                rollback.append({"session": session, "item": "vnfrs", "_id": vnfr_id, "force": True})
                nsr_descriptor["constituent-vnfr-ref"].append(vnfr_id)

            step = "creating nsr at database"
            self._format_new_data(session, "nsrs", nsr_descriptor)
            self.db.create("nsrs", nsr_descriptor)
            return nsr_id
        except Exception as e:
            raise EngineException("Error {}: {}".format(step, e))
            for rollback_item in rollback:
                try:
                    self.engine.del_item(**rollback)
                except Exception as e2:
                    self.logger.error("Rollback Exception {}: {}".format(rollback, e2))

    @staticmethod
    def _update_descriptor(desc, kwargs):
        """
        Update descriptor with the kwargs. It contains dot separated keys
        :param desc: dictionary to be updated
        :param kwargs: plain dictionary to be used for updating.
        :return:
        """
        if not kwargs:
            return
        try:
            for k, v in kwargs.items():
                update_content = desc
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

    def new_item(self, session, item, indata={}, kwargs=None, headers={}, force=False):
        """
        Creates a new entry into database. For nsds and vnfds it creates an almost empty DISABLED  entry,
        that must be completed with a call to method upload_content
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vim_accounts, sdns, nsrs, nsds, vnfds
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :return: _id: identity of the inserted data.
        """

        try:
            item_envelop = item
            if item in ("nsds", "vnfds"):
                item_envelop = "userDefinedData"
            content = self._remove_envelop(item_envelop, indata)

            # Override descriptor with query string kwargs
            self._update_descriptor(content, kwargs)
            if not indata and item not in ("nsds", "vnfds"):
                raise EngineException("Empty payload")

            validate_input(content, item, new=True)

            if item == "nsrs":
                # in this case the input descriptor is not the data to be stored
                return self.new_nsr(session, ns_request=content)

            self._validate_new_data(session, item_envelop, content, force)
            if item in ("nsds", "vnfds"):
                content = {"_admin": {"userDefinedData": content}}
            self._format_new_data(session, item, content)
            _id = self.db.create(item, content)

            if item == "vim_accounts":
                msg_data = self.db.get_one(item, {"_id": _id})
                msg_data.pop("_admin", None)
                self.msg.write("vim_account", "create", msg_data)
            elif item == "sdns":
                msg_data = self.db.get_one(item, {"_id": _id})
                msg_data.pop("_admin", None)
                self.msg.write("sdn", "create", msg_data)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def new_nslcmop(self, session, nsInstanceId, operation, params):
        now = time()
        _id = str(uuid4())
        nslcmop = {
            "id": _id,
            "_id": _id,
            "operationState": "PROCESSING",  # COMPLETED,PARTIALLY_COMPLETED,FAILED_TEMP,FAILED,ROLLING_BACK,ROLLED_BACK
            "statusEnteredTime": now,
            "nsInstanceId": nsInstanceId,
            "lcmOperationType": operation,
            "startTime": now,
            "isAutomaticInvocation": False,
            "operationParams": params,
            "isCancelPending": False,
            "links": {
                "self": "/osm/nslcm/v1/ns_lcm_op_occs/" + _id,
                "nsInstance": "/osm/nslcm/v1/ns_instances/" + nsInstanceId,
            }
        }
        return nslcmop

    def ns_operation(self, session, nsInstanceId, operation, indata, kwargs=None):
        """
        Performs a new operation over a ns
        :param session: contains the used login username and working project
        :param nsInstanceId: _id of the nsr to perform the operation
        :param operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param indata: descriptor with the parameters of the operation
        :param kwargs: used to override the indata descriptor
        :return: id of the nslcmops
        """
        try:
            # Override descriptor with query string kwargs
            self._update_descriptor(indata, kwargs)
            validate_input(indata, "ns_" + operation, new=True)
            # get ns from nsr_id
            nsr = self.get_item(session, "nsrs", nsInstanceId)
            if not nsr["_admin"].get("nsState") or nsr["_admin"]["nsState"] == "NOT_INSTANTIATED":
                if operation == "terminate" and indata.get("autoremove"):
                    # NSR must be deleted
                    return self.del_item(session, "nsrs", nsInstanceId)
                if operation != "instantiate":
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is not instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            else:
                if operation == "instantiate" and not indata.get("force"):
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is already instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            indata["nsInstanceId"] = nsInstanceId
            self._check_ns_operation(session, nsr, operation, indata)
            nslcmop = self.new_nslcmop(session, nsInstanceId, operation, indata)
            self._format_new_data(session, "nslcmops", nslcmop)
            _id = self.db.create("nslcmops", nslcmop)
            indata["_id"] = _id
            self.msg.write("ns", operation, nslcmop)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
        # except DbException as e:
        #     raise EngineException("Cannot get ns_instance '{}': {}".format(e), HTTPStatus.NOT_FOUND)

    def _add_read_filter(self, session, item, filter):
        if session["project_id"] == "admin":  # allows all
            return filter
        if item == "users":
            filter["username"] = session["username"]
        elif item in ("vnfds", "nsds", "nsrs"):
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

    def get_file(self, session, item, _id, path=None, accept_header=None):
        """
        Return the file content of a vnfd or nsd
        :param session: contains the used login username and working project
        :param item: it can be vnfds or nsds
        :param _id: Identity of the vnfd, ndsd
        :param path: artifact path or "$DESCRIPTOR" or None
        :param accept_header: Content of Accept header. Must contain applition/zip or/and text/plain
        :return: opened file or raises an exception
        """
        accept_text = accept_zip = False
        if accept_header:
            if 'text/plain' in accept_header or '*/*' in accept_header:
                accept_text = True
            if 'application/zip' in accept_header or '*/*' in accept_header:
                accept_zip = True
        if not accept_text and not accept_zip:
            raise EngineException("provide request header 'Accept' with 'application/zip' or 'text/plain'",
                                  http_code=HTTPStatus.NOT_ACCEPTABLE)

        content = self.get_item(session, item, _id)
        if content["_admin"]["onboardingState"] != "ONBOARDED":
            raise EngineException("Cannot get content because this resource is not at 'ONBOARDED' state. "
                                  "onboardingState is {}".format(content["_admin"]["onboardingState"]),
                                  http_code=HTTPStatus.CONFLICT)
        storage = content["_admin"]["storage"]
        if path is not None and path != "$DESCRIPTOR":   # artifacts
            if not storage.get('pkg-dir'):
                raise EngineException("Packages does not contains artifacts", http_code=HTTPStatus.BAD_REQUEST)
            if self.fs.file_exists((storage['folder'], storage['pkg-dir'], *path), 'dir'):
                folder_content = self.fs.dir_ls((storage['folder'], storage['pkg-dir'], *path))
                return folder_content, "text/plain"
                # TODO manage folders in http
            else:
                return self.fs.file_open((storage['folder'], storage['pkg-dir'], *path), "rb"), \
                       "application/octet-stream"

        # pkgtype   accept  ZIP  TEXT    -> result
        # manyfiles         yes  X       -> zip
        #                   no   yes     -> error
        # onefile           yes  no      -> zip
        #                   X    yes     -> text

        if accept_text and (not storage.get('pkg-dir') or path == "$DESCRIPTOR"):
            return self.fs.file_open((storage['folder'], storage['descriptor']), "r"), "text/plain"
        elif storage.get('pkg-dir') and not accept_zip:
            raise EngineException("Packages that contains several files need to be retrieved with 'application/zip'"
                                  "Accept header", http_code=HTTPStatus.NOT_ACCEPTABLE)
        else:
            if not storage.get('zipfile'):
                # TODO generate zipfile if not present
                raise EngineException("Only allowed 'text/plain' Accept header for this descriptor. To be solved in "
                                      "future versions", http_code=HTTPStatus.NOT_ACCEPTABLE)
            return self.fs.file_open((storage['folder'], storage['zipfile']), "rb"), "application/zip"

    def get_item_list(self, session, item, filter={}):
        """
        Get a list of items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param filter: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        # TODO add admin to filter, validate rights
        # TODO transform data for SOL005 URL requests. Transform filtering
        # TODO implement "field-type" query string SOL005

        self._add_read_filter(session, item, filter)
        return self.db.get_list(item, filter)

    def get_item(self, session, item, _id):
        """
        Get complete information on an items
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :return: dictionary, raise exception if not found.
        """
        filter = {"_id": _id}
        # TODO add admin to filter, validate rights
        # TODO transform data for SOL005 URL requests
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

    def del_item(self, session, item, _id, force=False):
        """
        Delete item by its internal id
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param _id: server id of the item
        :param force: indicates if deletion must be forced in case of conflict
        :return: dictionary with deleted item _id. It raises exception if not found.
        """
        # TODO add admin to filter, validate rights
        # data = self.get_item(item, _id)
        filter = {"_id": _id}
        self._add_delete_filter(session, item, filter)
        if item in ("vnfds", "nsds") and not force:
            descriptor = self.get_item(session, item, _id)
            descriptor_id = descriptor["id"]
            self._check_dependencies_on_descriptor(session, item, descriptor_id)

        if item == "nsrs":
            nsr = self.db.get_one(item, filter)
            if nsr["_admin"]["nsState"] == "INSTANTIATED" and not force:
                raise EngineException("nsr '{}' cannot be deleted because it is in 'INSTANTIATED' state. "
                                      "Launch 'terminate' operation first; or force deletion".format(_id),
                                      http_code=HTTPStatus.CONFLICT)
            v = self.db.del_one(item, {"_id": _id})
            self.db.del_list("nslcmops", {"nsInstanceId": _id})
            self.db.del_list("vnfrs", {"nsr-id-ref": _id})
            self.msg.write("ns", "deleted", {"_id": _id})
            return v
        if item in ("vim_accounts", "sdns"):
            desc = self.db.get_one(item, filter)
            desc["_admin"]["to_delete"] = True
            self.db.replace(item, _id, desc)   # TODO change to set_one
            if item == "vim_accounts":
                self.msg.write("vim_account", "delete", {"_id": _id})
            elif item == "sdns":
                self.msg.write("sdn", "delete", {"_id": _id})
            return {"deleted": 1}  # TODO indicate an offline operation to return 202 ACCEPTED

        v = self.db.del_one(item, filter)
        self.fs.file_delete(_id, ignore_non_exist=True)
        return v

    def prune(self):
        """
        Prune database not needed content
        :return: None
        """
        return self.db.del_list("nsrs", {"_admin.to_delete": True})

    def create_admin(self):
        """
        Creates a new user admin/admin into database if database is empty. Useful for initialization
        :return: _id identity of the inserted data, or None
        """
        users = self.db.get_one("users", fail_on_empty=False, fail_on_more=False)
        if users:
            return None
            # raise EngineException("Unauthorized. Database users is not empty", HTTPStatus.UNAUTHORIZED)
        indata = {"username": "admin", "password": "admin", "projects": ["admin"]}
        fake_session = {"project_id": "admin", "username": "admin"}
        self._format_new_data(fake_session, "users", indata)
        _id = self.db.create("users", indata)
        return _id

    def init_db(self, target_version='1.0'):
        """
        Init database if empty. If not empty it checks that database version is ok.
        If empty, it creates a new user admin/admin at 'users' and a new entry at 'version'
        :return: None if ok, exception if error or if the version is different.
        """
        version = self.db.get_one("version", fail_on_empty=False, fail_on_more=False)
        if not version:
            # create user admin
            self.create_admin()
            # create database version
            version_data = {
                "_id": '1.0',                     # version text
                "version": 1000,                  # version number
                "date": "2018-04-12",             # version date
                "description": "initial design",  # changes in this version
                'status': 'ENABLED'               # ENABLED, DISABLED (migration in process), ERROR,
            }
            self.db.create("version", version_data)
        elif version["_id"] != target_version:
            # TODO implement migration process
            raise EngineException("Wrong database version '{}'. Expected '{}'".format(
                version["_id"], target_version), HTTPStatus.INTERNAL_SERVER_ERROR)
        elif version["status"] != 'ENABLED':
            raise EngineException("Wrong database status '{}'".format(
                version["status"]), HTTPStatus.INTERNAL_SERVER_ERROR)
        return

    def _edit_item(self, session, item, id, content, indata={}, kwargs=None, force=False):
        if indata:
            indata = self._remove_envelop(item, indata)

        # Override descriptor with query string kwargs
        if kwargs:
            try:
                for k, v in kwargs.items():
                    update_content = indata
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
        try:
            validate_input(indata, item, new=False)
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

        _deep_update(content, indata)
        self._validate_new_data(session, item, content, id, force)
        # self._format_new_data(session, item, content)
        self.db.replace(item, id, content)
        if item in ("vim_accounts", "sdns"):
            indata.pop("_admin", None)
            indata["_id"] = id
            if item == "vim_accounts":
                self.msg.write("vim_account", "edit", indata)
            elif item == "sdns":
                self.msg.write("sdn", "edit", indata)
        return id

    def edit_item(self, session, item, _id, indata={}, kwargs=None, force=False):
        """
        Update an existing entry at database
        :param session: contains the used login username and working project
        :param item: it can be: users, projects, vnfds, nsds, ...
        :param _id: identifier to be updated
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param force: If True avoid some dependence checks
        :return: dictionary, raise exception if not found.
        """

        content = self.get_item(session, item, _id)
        return self._edit_item(session, item, _id, content, indata, kwargs, force)
