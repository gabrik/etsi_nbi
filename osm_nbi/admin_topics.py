# -*- coding: utf-8 -*-

# import logging
from uuid import uuid4
from hashlib import sha256
from http import HTTPStatus
from validation import user_new_schema, user_edit_schema, project_new_schema, project_edit_schema
from validation import vim_account_new_schema, vim_account_edit_schema, sdn_new_schema, sdn_edit_schema
from base_topic import BaseTopic, EngineException

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class UserTopic(BaseTopic):
    topic = "users"
    topic_msg = "users"
    schema_new = user_new_schema
    schema_edit = user_edit_schema

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    @staticmethod
    def _get_project_filter(session, write=False, show_all=True):
        """
        Generates a filter dictionary for querying database users.
        Current policy is admin can show all, non admin, only its own user.
        :param session: contains "username", if user is "admin" and the working "project_id"
        :param write: if operation is for reading (False) or writing (True)
        :param show_all:  if True it will show public or
        :return:
        """
        if session["admin"]:  # allows all
            return {}
        else:
            return {"username": session["username"]}

    def check_conflict_on_new(self, session, indata, force=False):
        # check username not exists
        if self.db.get_one(self.topic, {"username": indata.get("username")}, fail_on_empty=False, fail_on_more=False):
            raise EngineException("username '{}' exists".format(indata["username"]), HTTPStatus.CONFLICT)
        # check projects
        if not force:
            for p in indata["projects"]:
                if p == "admin":
                    continue
                if not self.db.get_one("projects", {"_id": p}, fail_on_empty=False, fail_on_more=False):
                    raise EngineException("project '{}' does not exists".format(p), HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, force=False):
        if _id == session["username"]:
            raise EngineException("You cannot delete your own user", http_code=HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, make_public=False)
        content["_id"] = content["username"]
        salt = uuid4().hex
        content["_admin"]["salt"] = salt
        if content.get("password"):
            content["password"] = sha256(content["password"].encode('utf-8') + salt.encode('utf-8')).hexdigest()

    @staticmethod
    def format_on_edit(final_content, edit_content):
        BaseTopic.format_on_edit(final_content, edit_content)
        if edit_content.get("password"):
            salt = uuid4().hex
            final_content["_admin"]["salt"] = salt
            final_content["password"] = sha256(edit_content["password"].encode('utf-8') +
                                               salt.encode('utf-8')).hexdigest()

    def edit(self, session, _id, indata=None, kwargs=None, force=False, content=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return BaseTopic.edit(self, session, _id, indata=indata, kwargs=kwargs, force=force, content=content)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return BaseTopic.new(self, rollback, session, indata=indata, kwargs=kwargs, headers=headers, force=force,
                             make_public=make_public)


class ProjectTopic(BaseTopic):
    topic = "projects"
    topic_msg = "projects"
    schema_new = project_new_schema
    schema_edit = project_edit_schema

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata, force=False):
        if not indata.get("name"):
            raise EngineException("missing 'name'")
        # check name not exists
        if self.db.get_one(self.topic, {"name": indata.get("name")}, fail_on_empty=False, fail_on_more=False):
            raise EngineException("name '{}' exists".format(indata["name"]), HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, None)
        content["_id"] = content["name"]

    def check_conflict_on_del(self, session, _id, force=False):
        if _id == session["project_id"]:
            raise EngineException("You cannot delete your own project", http_code=HTTPStatus.CONFLICT)
        if force:
            return
        _filter = {"projects": _id}
        if self.db.get_list("users", _filter):
            raise EngineException("There is some USER that contains this project", http_code=HTTPStatus.CONFLICT)

    def edit(self, session, _id, indata=None, kwargs=None, force=False, content=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return BaseTopic.edit(self, session, _id, indata=indata, kwargs=kwargs, force=force, content=content)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None, force=False, make_public=False):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        return BaseTopic.new(self, rollback, session, indata=indata, kwargs=kwargs, headers=headers, force=force,
                             make_public=make_public)


class VimAccountTopic(BaseTopic):
    topic = "vim_accounts"
    topic_msg = "vim_account"
    schema_new = vim_account_new_schema
    schema_edit = vim_account_edit_schema

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata, force=False):
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id, force=False):
        if edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=False)
        content["_admin"]["operationalState"] = "PROCESSING"

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
        if dry_run or force:    # delete completely
            return BaseTopic.delete(self, session, _id, force, dry_run)
        else:  # if not, sent to kafka
            v = BaseTopic.delete(self, session, _id, force, dry_run=True)
            self.db.set_one("vim_accounts", {"_id": _id}, {"_admin.to_delete": True})  # TODO change status
            self._send_msg("delete", {"_id": _id})
            return v  # TODO indicate an offline operation to return 202 ACCEPTED


class SdnTopic(BaseTopic):
    topic = "sdns"
    topic_msg = "sdn"
    schema_new = sdn_new_schema
    schema_edit = sdn_edit_schema

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata, force=False):
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id, force=False):
        if edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=False)
        content["_admin"]["operationalState"] = "PROCESSING"

    def delete(self, session, _id, force=False, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains the used login username, working project, and admin rights
        :param _id: server internal id
        :param force: indicates if deletion must be forced in case of conflict
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        if dry_run or force:  # delete completely
            return BaseTopic.delete(self, session, _id, force, dry_run)
        else:  # if not sent to kafka
            v = BaseTopic.delete(self, session, _id, force, dry_run=True)
            self.db.set_one("sdns", {"_id": _id}, {"_admin.to_delete": True})  # TODO change status
            self._send_msg("delete", {"_id": _id})
            return v   # TODO indicate an offline operation to return 202 ACCEPTED