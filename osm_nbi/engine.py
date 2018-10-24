# -*- coding: utf-8 -*-

import logging
from osm_common import dbmongo, dbmemory, fslocal, msglocal, msgkafka, version as common_version
from osm_common.dbbase import DbException
from osm_common.fsbase import FsException
from osm_common.msgbase import MsgException
from http import HTTPStatus
from base_topic import EngineException, versiontuple
from admin_topics import UserTopic, ProjectTopic, VimAccountTopic, SdnTopic
from descriptor_topics import VnfdTopic, NsdTopic, PduTopic
from instance_topics import NsrTopic, VnfrTopic, NsLcmOpTopic

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
min_common_version = "0.1.8"


class Engine(object):
    map_from_topic_to_class = {
        "vnfds": VnfdTopic,
        "nsds": NsdTopic,
        "pdus": PduTopic,
        "nsrs": NsrTopic,
        "vnfrs": VnfrTopic,
        "nslcmops": NsLcmOpTopic,
        "vim_accounts": VimAccountTopic,
        "sdns": SdnTopic,
        "users": UserTopic,
        "projects": ProjectTopic,
        # [NEW_TOPIC]: add an entry here
    }

    def __init__(self):
        self.db = None
        self.fs = None
        self.msg = None
        self.config = None
        self.logger = logging.getLogger("nbi.engine")
        self.map_topic = {}

    def start(self, config):
        """
        Connect to database, filesystem storage, and messaging
        :param config: two level dictionary with configuration. Top level should contain 'database', 'storage',
        :return: None
        """
        self.config = config
        # check right version of common
        if versiontuple(common_version) < versiontuple(min_common_version):
            raise EngineException("Not compatible osm/common version '{}'. Needed '{}' or higher".format(
                common_version, min_common_version))

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

            # create one class per topic
            for topic, topic_class in self.map_from_topic_to_class.items():
                self.map_topic[topic] = topic_class(self.db, self.fs, self.msg)
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

    def new_item(self, rollback, session, topic, indata=None, kwargs=None, headers=None, force=False):
        """
        Creates a new entry into database. For nsds and vnfds it creates an almost empty DISABLED  entry,
        that must be completed with a call to method upload_content
        :param rollback: list to append created items at database in case a rollback must to be done
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vim_accounts, sdns, nsrs, nsds, vnfds
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :return: _id: identity of the inserted data.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].new(rollback, session, indata, kwargs, headers, force)

    def upload_content(self, session, topic, _id, indata, kwargs, headers, force=False):
        """
        Upload content for an already created entry (_id)
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :param force: If True avoid some dependence checks
        :return: _id: identity of the inserted data.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].upload_content(session, _id, indata, kwargs, headers, force)

    def get_item_list(self, session, topic, filter_q=None):
        """
        Get a list of items
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter_q.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].list(session, filter_q)

    def get_item(self, session, topic, _id):
        """
        Get complete information on an item
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :return: dictionary, raise exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].show(session, _id)

    def get_file(self, session, topic, _id, path=None, accept_header=None):
        """
        Get descriptor package or artifact file content
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds,
        :param _id: server id of the item
        :param path: artifact path or "$DESCRIPTOR" or None
        :param accept_header: Content of Accept header. Must contain applition/zip or/and text/plain
        :return: opened file plus Accept format or raises an exception
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].get_file(session, _id, path, accept_header)

    def del_item_list(self, session, topic, _filter=None):
        """
        Delete a list of items
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _filter: filter of data to be applied
        :return: The deleted list, it can be empty if no one match the _filter.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].delete_list(session, _filter)

    def del_item(self, session, topic, _id, force=False):
        """
        Delete item by its internal id
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _id: server id of the item
        :param force: indicates if deletion must be forced in case of conflict
        :return: dictionary with deleted item _id. It raises exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].delete(session, _id, force)

    def edit_item(self, session, topic, _id, indata=None, kwargs=None, force=False):
        """
        Update an existing entry at database
        :param session: contains the used login username and working project
        :param topic: it can be: users, projects, vnfds, nsds, ...
        :param _id: identifier to be updated
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param force: If True avoid some dependence checks
        :return: dictionary, raise exception if not found.
        """
        if topic not in self.map_topic:
            raise EngineException("Unknown topic {}!!!".format(topic), HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.map_topic[topic].edit(session, _id, indata, kwargs, force)

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
        user_desc = {"username": "admin", "password": "admin", "projects": ["admin"]}
        fake_session = {"project_id": "admin", "username": "admin", "admin": True}
        roolback_list = []
        _id = self.map_topic["users"].new(roolback_list, fake_session, user_desc, force=True)
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
