# -*- coding: utf-8 -*-

# import logging
from uuid import uuid4
from http import HTTPStatus
from time import time
from copy import copy
from validation import validate_input, ValidationError, ns_instantiate, ns_action, ns_scale
from base_topic import BaseTopic, EngineException, get_iterable
from descriptor_topics import DescriptorTopic

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class NsrTopic(BaseTopic):
    topic = "nsrs"
    topic_msg = "ns"

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def _check_descriptor_dependencies(self, session, descriptor):
        """
        Check that the dependent descriptors exist on a new descriptor or edition
        :param session: client session information
        :param descriptor: descriptor to be inserted or edit
        :return: None or raises exception
        """
        if not descriptor.get("nsdId"):
            return
        nsd_id = descriptor["nsdId"]
        if not self.get_item_list(session, "nsds", {"id": nsd_id}):
            raise EngineException("Descriptor error at nsdId='{}' references a non exist nsd".format(nsd_id),
                                  http_code=HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["_admin"]["nsState"] = "NOT_INSTANTIATED"

    def check_conflict_on_del(self, session, _id, force=False):
        if force:
            return
        nsr = self.db.get_one("nsrs", {"_id": _id})
        if nsr["_admin"].get("nsState") == "INSTANTIATED":
            raise EngineException("nsr '{}' cannot be deleted because it is in 'INSTANTIATED' state. "
                                  "Launch 'terminate' operation first; or force deletion".format(_id),
                                  http_code=HTTPStatus.CONFLICT)

    def delete(self, session, _id, force=False, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains the used login username, working project, and admin rights
        :param _id: server internal id
        :param force: indicates if deletion must be forced in case of conflict
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        # TODO add admin to filter, validate rights
        BaseTopic.delete(self, session, _id, force, dry_run=True)
        if dry_run:
            return

        v = self.db.del_one("nsrs", {"_id": _id})
        self.db.del_list("nslcmops", {"nsInstanceId": _id})
        self.db.del_list("vnfrs", {"nsr-id-ref": _id})
        # set all used pdus as free
        self.db.set_list("pdus", {"_admin.usage.nsr_id": _id},
                         {"_admin.usageSate": "NOT_IN_USE", "_admin.usage": None})
        self._send_msg("deleted", {"_id": _id})
        return v

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        """
        Creates a new nsr into database. It also creates needed vnfrs
        :param rollback: list to append the created items at database in case a rollback must be done
        :param session: contains the used login username and working project
        :param indata: params to be used for the nsr
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :param make_public: Make the created item public to all projects
        :return: the _id of nsr descriptor created at database
        """

        try:
            ns_request = self._remove_envelop(indata)
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(ns_request, kwargs)
            self._validate_input_new(ns_request, force)

            step = ""
            # look for nsr
            step = "getting nsd id='{}' from database".format(ns_request.get("nsdId"))
            _filter = {"_id": ns_request["nsdId"]}
            _filter.update(BaseTopic._get_project_filter(session, write=False, show_all=True))
            nsd = self.db.get_one("nsds", _filter)

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
                    vnfd = DescriptorTopic.get_one_by_id(self.db, session, "vnfds", vnfd_id)
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
                    "vnfd-id": vnfd["_id"],    # not at OSM model, but useful
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
                        # TODO      "name": ""     Name of the VDU in the VIM
                        "ip-address": None,  # mgmt-interface filled by LCM
                        # "vim-id", "flavor-id", "image-id", "management-ip" # filled by LCM
                        "internal-connection-point": [],
                        "interfaces": [],
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
                    for iface in vdu.get("interface", ()):
                        vdu_iface = {
                            "name": iface.get("name"),
                            # "ip-address", "mac-address" # filled by LCM
                            # vim-id  # TODO it would be nice having a vim port id
                        }
                        vdur["interfaces"].append(vdu_iface)
                    vnfr_descriptor["vdur"].append(vdur)

                step = "creating vnfr vnfd-id='{}' constituent-vnfd='{}' at database".format(
                    member_vnf["vnfd-id-ref"], member_vnf["member-vnf-index"])

                # add at database
                BaseTopic.format_on_new(vnfr_descriptor, session["project_id"], make_public=make_public)
                self.db.create("vnfrs", vnfr_descriptor)
                rollback.append({"topic": "vnfrs", "_id": vnfr_id})
                nsr_descriptor["constituent-vnfr-ref"].append(vnfr_id)

            step = "creating nsr at database"
            self.format_on_new(nsr_descriptor, session["project_id"], make_public=make_public)
            self.db.create("nsrs", nsr_descriptor)
            rollback.append({"topic": "nsrs", "_id": nsr_id})
            return nsr_id
        except Exception as e:
            self.logger.exception("Exception {} at NsrTopic.new()".format(e), exc_info=True)
            raise EngineException("Error {}: {}".format(step, e))
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def edit(self, session, _id, indata=None, kwargs=None, force=False, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class VnfrTopic(BaseTopic):
    topic = "vnfrs"
    topic_msg = None

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def delete(self, session, _id, force=False, dry_run=False):
        raise EngineException("Method delete called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def edit(self, session, _id, indata=None, kwargs=None, force=False, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        # Not used because vnfrs are created and deleted by NsrTopic class directly
        raise EngineException("Method new called directly", HTTPStatus.INTERNAL_SERVER_ERROR)


class NsLcmOpTopic(BaseTopic):
    topic = "nslcmops"
    topic_msg = "ns"
    operation_schema = {    # mapping between operation and jsonschema to validate
        "instantiate": ns_instantiate,
        "action": ns_action,
        "scale": ns_scale,
        "terminate": None,
    }

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def _validate_input_new(self, input, force=False):
        """
        Validates input user content for a new entry. It uses jsonschema for each type or operation.
        :param input: user input content for the new topic
        :param force: may be used for being more tolerant
        :return: The same input content, or a changed version of it.
        """
        if self.schema_new:
            validate_input(input, self.schema_new)
        return input

    def _check_ns_operation(self, session, nsr, operation, indata):
        """
        Check that user has enter right parameters for the operation
        :param session:
        :param operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param indata: descriptor with the parameters of the operation
        :return: None
        """
        vnfds = {}
        vim_accounts = []
        nsd = nsr["nsd"]

        def check_valid_vnf_member_index(member_vnf_index):
            # TODO change to vnfR
            for vnf in nsd["constituent-vnfd"]:
                if member_vnf_index == vnf["member-vnf-index"]:
                    vnfd_id = vnf["vnfd-id-ref"]
                    if vnfd_id not in vnfds:
                        vnfds[vnfd_id] = self.db.get_one("vnfds", {"id": vnfd_id})
                    return vnfds[vnfd_id]
            else:
                raise EngineException("Invalid parameter member_vnf_index='{}' is not one of the "
                                      "nsd:constituent-vnfd".format(member_vnf_index))

        def check_valid_vim_account(vim_account):
            if vim_account in vim_accounts:
                return
            try:
                # TODO add _get_project_filter
                self.db.get_one("vim_accounts", {"_id": vim_account})
            except Exception:
                raise EngineException("Invalid vimAccountId='{}' not present".format(vim_account))
            vim_accounts.append(vim_account)

        if operation == "action":
            # check vnf_member_index
            if indata.get("vnf_member_index"):
                indata["member_vnf_index"] = indata.pop("vnf_member_index")    # for backward compatibility
            if not indata.get("member_vnf_index"):
                raise EngineException("Missing 'member_vnf_index' parameter")
            vnfd = check_valid_vnf_member_index(indata["member_vnf_index"])
            # check primitive
            for config_primitive in get_iterable(vnfd.get("vnf-configuration", {}).get("config-primitive")):
                if indata["primitive"] == config_primitive["name"]:
                    # check needed primitive_params are provided
                    if indata.get("primitive_params"):
                        in_primitive_params_copy = copy(indata["primitive_params"])
                    else:
                        in_primitive_params_copy = {}
                    for paramd in get_iterable(config_primitive.get("parameter")):
                        if paramd["name"] in in_primitive_params_copy:
                            del in_primitive_params_copy[paramd["name"]]
                        elif not paramd.get("default-value"):
                            raise EngineException("Needed parameter {} not provided for primitive '{}'".format(
                                paramd["name"], indata["primitive"]))
                    # check no extra primitive params are provided
                    if in_primitive_params_copy:
                        raise EngineException("parameter/s '{}' not present at vnfd for primitive '{}'".format(
                            list(in_primitive_params_copy.keys()), indata["primitive"]))
                    break
            else:
                raise EngineException("Invalid primitive '{}' is not present at vnfd".format(indata["primitive"]))
        if operation == "scale":
            vnfd = check_valid_vnf_member_index(indata["scaleVnfData"]["scaleByStepData"]["member-vnf-index"])
            for scaling_group in get_iterable(vnfd.get("scaling-group-descriptor")):
                if indata["scaleVnfData"]["scaleByStepData"]["scaling-group-descriptor"] == scaling_group["name"]:
                    break
            else:
                raise EngineException("Invalid scaleVnfData:scaleByStepData:scaling-group-descriptor '{}' is not "
                                      "present at vnfd:scaling-group-descriptor".format(
                                          indata["scaleVnfData"]["scaleByStepData"]["scaling-group-descriptor"]))
        if operation == "instantiate":
            # check vim_account
            check_valid_vim_account(indata["vimAccountId"])
            for in_vnf in get_iterable(indata.get("vnf")):
                vnfd = check_valid_vnf_member_index(in_vnf["member-vnf-index"])
                if in_vnf.get("vimAccountId"):
                    check_valid_vim_account(in_vnf["vimAccountId"])
                for in_vdu in get_iterable(in_vnf.get("vdu")):
                    for vdud in get_iterable(vnfd.get("vdu")):
                        if vdud["id"] == in_vdu["id"]:
                            for volume in get_iterable(in_vdu.get("volume")):
                                for volumed in get_iterable(vdud.get("volumes")):
                                    if volumed["name"] == volume["name"]:
                                        break
                                else:
                                    raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:vdu[id='{}']:"
                                                          "volume:name='{}' is not present at vnfd:vdu:volumes list".
                                                          format(in_vnf["member-vnf-index"], in_vdu["id"],
                                                                 volume["name"]))
                            break
                    else:
                        raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:vdu:id='{}' is not "
                                              "present at vnfd".format(in_vnf["member-vnf-index"], in_vdu["id"]))

                for in_internal_vld in get_iterable(in_vnf.get("internal-vld")):
                    for internal_vldd in get_iterable(vnfd.get("internal-vld")):
                        if in_internal_vld["name"] == internal_vldd["name"] or \
                                in_internal_vld["name"] == internal_vldd["id"]:
                            break
                    else:
                        raise EngineException("Invalid parameter vnf[member-vnf-index='{}']:internal-vld:name='{}'"
                                              " is not present at vnfd '{}'".format(in_vnf["member-vnf-index"],
                                                                                    in_internal_vld["name"],
                                                                                    vnfd["id"]))
            for in_vld in get_iterable(indata.get("vld")):
                for vldd in get_iterable(nsd.get("vld")):
                    if in_vld["name"] == vldd["name"] or in_vld["name"] == vldd["id"]:
                        break
                else:
                    raise EngineException("Invalid parameter vld:name='{}' is not present at nsd:vld".format(
                        in_vld["name"]))

    def _create_nslcmop(self, session, nsInstanceId, operation, params):
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

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        """
        Performs a new operation over a ns
        :param rollback: list to append created items at database in case a rollback must to be done
        :param session: contains the used login username and working project
        :param indata: descriptor with the parameters of the operation. It must contains among others
            nsInstanceId: _id of the nsr to perform the operation
            operation: it can be: instantiate, terminate, action, TODO: update, heal
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :param make_public: Make the created item public to all projects
        :return: id of the nslcmops
        """
        try:
            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(indata, kwargs)
            operation = indata["lcmOperationType"]
            nsInstanceId = indata["nsInstanceId"]

            validate_input(indata, self.operation_schema[operation])
            # get ns from nsr_id
            _filter = BaseTopic._get_project_filter(session, write=True, show_all=False)
            _filter["_id"] = nsInstanceId
            nsr = self.db.get_one("nsrs", _filter)

            # initial checking
            if not nsr["_admin"].get("nsState") or nsr["_admin"]["nsState"] == "NOT_INSTANTIATED":
                if operation == "terminate" and indata.get("autoremove"):
                    # NSR must be deleted
                    return self.delete(session, nsInstanceId)
                if operation != "instantiate":
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is not instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            else:
                if operation == "instantiate" and not indata.get("force"):
                    raise EngineException("ns_instance '{}' cannot be '{}' because it is already instantiated".format(
                        nsInstanceId, operation), HTTPStatus.CONFLICT)
            self._check_ns_operation(session, nsr, operation, indata)
            nslcmop_desc = self._create_nslcmop(session, nsInstanceId, operation, indata)
            self.format_on_new(nslcmop_desc, session["project_id"], make_public=make_public)
            _id = self.db.create("nslcmops", nslcmop_desc)
            rollback.append({"topic": "nslcmops", "_id": _id})
            self.msg.write("ns", operation, nslcmop_desc)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
        # except DbException as e:
        #     raise EngineException("Cannot get ns_instance '{}': {}".format(e), HTTPStatus.NOT_FOUND)

    def delete(self, session, _id, force=False, dry_run=False):
        raise EngineException("Method delete called directly", HTTPStatus.INTERNAL_SERVER_ERROR)

    def edit(self, session, _id, indata=None, kwargs=None, force=False, content=None):
        raise EngineException("Method edit called directly", HTTPStatus.INTERNAL_SERVER_ERROR)
