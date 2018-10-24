# -*- coding: utf-8 -*-

import tarfile
import yaml
import json
# import logging
from hashlib import md5
from osm_common.dbbase import DbException, deep_update_rfc7396
from http import HTTPStatus
from validation import ValidationError, pdu_new_schema, pdu_edit_schema
from base_topic import BaseTopic, EngineException

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class DescriptorTopic(BaseTopic):

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id, force=False):
        # check that this id is not present
        _filter = {"id": final_content["id"]}
        if _id:
            _filter["_id.neq"] = _id

        _filter.update(self._get_project_filter(session, write=False, show_all=False))
        if self.db.get_one(self.topic, _filter, fail_on_empty=False):
            raise EngineException("{} with id '{}' already exists for this project".format(self.topic[:-1],
                                                                                           final_content["id"]),
                                  HTTPStatus.CONFLICT)
        # TODO validate with pyangbind. Load and dumps to convert data types

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["_admin"]["onboardingState"] = "CREATED"
        content["_admin"]["operationalState"] = "DISABLED"
        content["_admin"]["usageSate"] = "NOT_IN_USE"

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
        v = BaseTopic.delete(self, session, _id, force, dry_run=True)
        if dry_run:
            return
        v = self.db.del_one(self.topic, {"_id": _id})
        self.fs.file_delete(_id, ignore_non_exist=True)
        self._send_msg("delete", {"_id": _id})
        return v

    @staticmethod
    def get_one_by_id(db, session, topic, id):
        # find owned by this project
        _filter = BaseTopic._get_project_filter(session, write=False, show_all=False)
        _filter["id"] = id
        desc_list = db.get_list(topic, _filter)
        if len(desc_list) == 1:
            return desc_list[0]
        elif len(desc_list) > 1:
            raise DbException("Found more than one {} with id='{}' belonging to this project".format(topic[:-1], id),
                              HTTPStatus.CONFLICT)

        # not found any: try to find public
        _filter = BaseTopic._get_project_filter(session, write=False, show_all=True)
        _filter["id"] = id
        desc_list = db.get_list(topic, _filter)
        if not desc_list:
            raise DbException("Not found any {} with id='{}'".format(topic[:-1], id), HTTPStatus.NOT_FOUND)
        elif len(desc_list) == 1:
            return desc_list[0]
        else:
            raise DbException("Found more than one public {} with id='{}'; and no one belonging to this project".format(
                topic[:-1], id), HTTPStatus.CONFLICT)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        """
        Creates a new almost empty DISABLED  entry into database. Due to SOL005, it does not follow normal procedure.
        Creating a VNFD or NSD is done in two steps: 1. Creates an empty descriptor (this step) and 2) upload content
        (self.upload_content)
        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains the used login username and working project
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :param make_public: Make the created descriptor public to all projects
        :return: _id: identity of the inserted data.
        """

        try:
            # _remove_envelop
            if indata:
                if "userDefinedData" in indata:
                    indata = indata['userDefinedData']

            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(indata, kwargs)
            # uncomment when this method is implemented.
            # Avoid override in this case as the target is userDefinedData, but not vnfd,nsd descriptors
            # indata = DescriptorTopic._validate_input_new(self, indata, force=force)

            content = {"_admin": {"userDefinedData": indata}}
            self.format_on_new(content, session["project_id"], make_public=make_public)
            _id = self.db.create(self.topic, content)
            rollback.append({"topic": self.topic, "_id": _id})
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def upload_content(self, session, _id, indata, kwargs, headers, force=False):
        """
        Used for receiving content by chunks (with a transaction_id header and/or gzip file. It will store and extract)
        :param session: session
        :param _id : the nsd,vnfd is already created, this is the id
        :param indata: http body request
        :param kwargs: user query string to override parameters. NOT USED
        :param headers:  http request headers
        :param force: to be more tolerant with validation
        :return: True package has is completely uploaded or False if partial content has been uplodaed.
            Raise exception on error
        """
        # Check that _id exists and it is valid
        current_desc = self.show(session, _id)

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

            indata = self._remove_envelop(indata)

            # Override descriptor with query string kwargs
            if kwargs:
                self._update_input_with_kwargs(indata, kwargs)
            # it will call overrides method at VnfdTopic or NsdTopic
            indata = self._validate_input_new(indata, force=force)

            deep_update_rfc7396(current_desc, indata)
            self.check_conflict_on_edit(session, current_desc, indata, _id=_id, force=force)
            self.db.replace(self.topic, _id, current_desc)

            indata["_id"] = _id
            self._send_msg("created", indata)

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
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
        finally:
            if file_pkg:
                file_pkg.close()

    def get_file(self, session, _id, path=None, accept_header=None):
        """
        Return the file content of a vnfd or nsd
        :param session: contains the used login username and working project
        :param _id: Identity of the vnfd, nsd
        :param path: artifact path or "$DESCRIPTOR" or None
        :param accept_header: Content of Accept header. Must contain applition/zip or/and text/plain
        :return: opened file plus Accept format or raises an exception
        """
        accept_text = accept_zip = False
        if accept_header:
            if 'text/plain' in accept_header or '*/*' in accept_header:
                accept_text = True
            if 'application/zip' in accept_header or '*/*' in accept_header:
                accept_zip = 'application/zip'
            elif 'application/gzip' in accept_header:
                accept_zip = 'application/gzip'

        if not accept_text and not accept_zip:
            raise EngineException("provide request header 'Accept' with 'application/zip' or 'text/plain'",
                                  http_code=HTTPStatus.NOT_ACCEPTABLE)

        content = self.show(session, _id)
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
                return self.fs.file_open((storage['folder'], storage['pkg-dir'], *path), "rb"),\
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
            return self.fs.file_open((storage['folder'], storage['zipfile']), "rb"), accept_zip


class VnfdTopic(DescriptorTopic):
    topic = "vnfds"
    topic_msg = "vnfd"

    def __init__(self, db, fs, msg):
        DescriptorTopic.__init__(self, db, fs, msg)

    @staticmethod
    def _remove_envelop(indata=None):
        if not indata:
            return {}
        clean_indata = indata
        if clean_indata.get('vnfd:vnfd-catalog'):
            clean_indata = clean_indata['vnfd:vnfd-catalog']
        elif clean_indata.get('vnfd-catalog'):
            clean_indata = clean_indata['vnfd-catalog']
        if clean_indata.get('vnfd'):
            if not isinstance(clean_indata['vnfd'], list) or len(clean_indata['vnfd']) != 1:
                raise EngineException("'vnfd' must be a list only one element")
            clean_indata = clean_indata['vnfd'][0]
        return clean_indata

    def check_conflict_on_del(self, session, _id, force=False):
        """
        Check that there is not any NSD that uses this VNFD. Only NSDs belonging to this project are considered. Note
        that VNFD can be public and be used by NSD of other projects. Also check there are not deployments, or vnfr
        that uses this vnfd
        :param session:
        :param _id: vnfd inernal id
        :param force: Avoid this checking
        :return: None or raises EngineException with the conflict
        """
        if force:
            return
        descriptor = self.db.get_one("vnfds", {"_id": _id})
        descriptor_id = descriptor.get("id")
        if not descriptor_id:  # empty vnfd not uploaded
            return

        _filter = self._get_project_filter(session, write=False, show_all=False)
        # check vnfrs using this vnfd
        _filter["vnfd-id"] = _id
        if self.db.get_list("vnfrs", _filter):
            raise EngineException("There is some VNFR that depends on this VNFD", http_code=HTTPStatus.CONFLICT)
        del _filter["vnfd-id"]
        # check NSD using this VNFD
        _filter["constituent-vnfd.ANYINDEX.vnfd-id-ref"] = descriptor_id
        if self.db.get_list("nsds", _filter):
            raise EngineException("There is soame NSD that depends on this VNFD", http_code=HTTPStatus.CONFLICT)

    def _validate_input_new(self, indata, force=False):
        # TODO validate with pyangbind, serialize
        return indata

    def _validate_input_edit(self, indata, force=False):
        # TODO validate with pyangbind, serialize
        return indata


class NsdTopic(DescriptorTopic):
    topic = "nsds"
    topic_msg = "nsd"

    def __init__(self, db, fs, msg):
        DescriptorTopic.__init__(self, db, fs, msg)

    @staticmethod
    def _remove_envelop(indata=None):
        if not indata:
            return {}
        clean_indata = indata

        if clean_indata.get('nsd:nsd-catalog'):
            clean_indata = clean_indata['nsd:nsd-catalog']
        elif clean_indata.get('nsd-catalog'):
            clean_indata = clean_indata['nsd-catalog']
        if clean_indata.get('nsd'):
            if not isinstance(clean_indata['nsd'], list) or len(clean_indata['nsd']) != 1:
                raise EngineException("'nsd' must be a list only one element")
            clean_indata = clean_indata['nsd'][0]
        return clean_indata

    def _validate_input_new(self, indata, force=False):
        # transform constituent-vnfd:member-vnf-index to string
        if indata.get("constituent-vnfd"):
            for constituent_vnfd in indata["constituent-vnfd"]:
                if "member-vnf-index" in constituent_vnfd:
                    constituent_vnfd["member-vnf-index"] = str(constituent_vnfd["member-vnf-index"])

        # TODO validate with pyangbind, serialize
        return indata

    def _validate_input_edit(self, indata, force=False):
        # TODO validate with pyangbind, serialize
        return indata

    def _check_descriptor_dependencies(self, session, descriptor):
        """
        Check that the dependent descriptors exist on a new descriptor or edition
        :param session: client session information
        :param descriptor: descriptor to be inserted or edit
        :return: None or raises exception
        """
        if not descriptor.get("constituent-vnfd"):
            return
        for vnf in descriptor["constituent-vnfd"]:
            vnfd_id = vnf["vnfd-id-ref"]
            filter_q = self._get_project_filter(session, write=False, show_all=True)
            filter_q["id"] = vnfd_id
            if not self.db.get_list("vnfds", filter_q):
                raise EngineException("Descriptor error at 'constituent-vnfd':'vnfd-id-ref'='{}' references a non "
                                      "existing vnfd".format(vnfd_id), http_code=HTTPStatus.CONFLICT)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id, force=False):
        super().check_conflict_on_edit(session, final_content, edit_content, _id, force=force)

        self._check_descriptor_dependencies(session, final_content)

    def check_conflict_on_del(self, session, _id, force=False):
        """
        Check that there is not any NSR that uses this NSD. Only NSRs belonging to this project are considered. Note
        that NSD can be public and be used by other projects.
        :param session:
        :param _id: vnfd inernal id
        :param force: Avoid this checking
        :return: None or raises EngineException with the conflict
        """
        if force:
            return
        _filter = self._get_project_filter(session, write=False, show_all=False)
        _filter["nsdId"] = _id
        if self.db.get_list("nsrs", _filter):
            raise EngineException("There is some NSR that depends on this NSD", http_code=HTTPStatus.CONFLICT)


class PduTopic(BaseTopic):
    topic = "pdus"
    topic_msg = "pdu"
    schema_new = pdu_new_schema
    schema_edit = pdu_edit_schema

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=None, make_public=make_public)
        content["_admin"]["onboardingState"] = "CREATED"
        content["_admin"]["operationalState"] = "DISABLED"
        content["_admin"]["usageSate"] = "NOT_IN_USE"

    def check_conflict_on_del(self, session, _id, force=False):
        if force:
            return
        # TODO Is it needed to check descriptors _admin.project_read/project_write??
        _filter = {"vdur.pdu-id": _id}
        if self.db.get_list("vnfrs", _filter):
            raise EngineException("There is some NSR that uses this PDU", http_code=HTTPStatus.CONFLICT)
