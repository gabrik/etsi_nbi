#! /usr/bin/python3
# -*- coding: utf-8 -*-

import getopt
import sys
import requests
import json
import logging
import yaml
# import json
# import tarfile
from time import sleep
import os

__author__ = "Alfonso Tierno, alfonso.tiernosepulveda@telefonica.com"
__date__ = "$2018-03-01$"
__version__ = "0.3"
version_date = "Oct 2018"


def usage():
    print("Usage: ", sys.argv[0], "[options]")
    print("      Performs system tests over running NBI. It can be used for real OSM test using option '--test-osm'")
    print("      If this is the case env variables 'OSMNBITEST_VIM_NAME' must be suplied to create a VIM if not exist "
          "where deployment is done")
    print("OPTIONS")
    print("      -h|--help: shows this help")
    print("      --insecure: Allows non trusted https NBI server")
    print("      --list: list available tests")
    print("      --manual-check: Deployment tests stop after deployed to allow manual inspection. Only make sense with "
          "'--test-osm'")
    print("      -p|--password PASSWORD: NBI access password. 'admin' by default")
    print("      ---project PROJECT: NBI access project. 'admin' by default")
    print("      --test TEST[,...]: Execute only a test or a comma separated list of tests")
    print("      --params key=val: params to the previous test. key can be vnfd-files, nsd-file, ns-name, ns-config")
    print("      --test-osm: If missing this test is intended for NBI only, no other OSM components are expected. Use "
          "this flag to test the system. LCM and RO components are expected to be up and running")
    print("      --timeout TIMEOUT: General NBI timeout, by default {}s".format(timeout))
    print("      --timeout-deploy TIMEOUT: Timeout used for getting NS deployed, by default {}s".format(timeout_deploy))
    print("      --timeout-configure TIMEOUT: Timeout used for getting NS deployed and configured,"
          " by default {}s".format(timeout_configure))
    print("      -u|--user USERNAME: NBI access username. 'admin' by default")
    print("      --url URL: complete NBI server URL. 'https//localhost:9999/osm' by default")
    print("      -v|--verbose print debug information, can be used several times")
    print("      --no-verbose remove verbosity")
    print("      --version: prints current version")
    print("ENV variables used for real deployment tests with option osm-test.")
    print("      export OSMNBITEST_VIM_NAME=vim-name")
    print("      export OSMNBITEST_VIM_URL=vim-url")
    print("      export OSMNBITEST_VIM_TYPE=vim-type")
    print("      export OSMNBITEST_VIM_TENANT=vim-tenant")
    print("      export OSMNBITEST_VIM_USER=vim-user")
    print("      export OSMNBITEST_VIM_PASSWORD=vim-password")
    print("      export OSMNBITEST_VIM_CONFIG=\"vim-config\"")
    print("      export OSMNBITEST_NS_NAME=\"vim-config\"")
    return


r_header_json = {"Content-type": "application/json"}
headers_json = {
    "Content-type": "application/json",
    "Accept": "application/json",
}
r_header_yaml = {"Content-type": "application/yaml"}
headers_yaml = {
    "Content-type": "application/yaml",
    "Accept": "application/yaml",
}
r_header_text = {"Content-type": "text/plain"}
r_header_octect = {"Content-type": "application/octet-stream"}
headers_text = {
    "Accept": "text/plain",
}
r_header_zip = {"Content-type": "application/zip"}
headers_zip = {
    "Accept": "application/zip",
}
headers_zip_yaml = {
    "Accept": "application/yaml", "Content-type": "application/zip"
}


# test ones authorized
test_authorized_list = (
    ("AU1", "Invalid vnfd id", "GET", "/vnfpkgm/v1/vnf_packages/non-existing-id",
     headers_json, None, 404, r_header_json, "json"),
    ("AU2", "Invalid nsd id", "GET", "/nsd/v1/ns_descriptors/non-existing-id",
     headers_yaml, None, 404, r_header_yaml, "yaml"),
    ("AU3", "Invalid nsd id", "DELETE", "/nsd/v1/ns_descriptors_content/non-existing-id",
     headers_yaml, None, 404, r_header_yaml, "yaml"),
)
timeout = 120   # general timeout
timeout_deploy = 60*10        # timeout for NS deploying without charms
timeout_configure = 60*20     # timeout for NS deploying and configuring


class TestException(Exception):
    pass


class TestRest:
    def __init__(self, url_base, header_base=None, verify=False, user="admin", password="admin", project="admin"):
        self.url_base = url_base
        if header_base is None:
            self.header_base = {}
        else:
            self.header_base = header_base.copy()
        self.s = requests.session()
        self.s.headers = self.header_base
        self.verify = verify
        self.token = False
        self.user = user
        self.password = password
        self.project = project
        self.vim_id = None
        # contains ID of tests obtained from Location response header. "" key contains last obtained id
        self.test_ids = {}
        self.old_test_description = ""

    def set_header(self, header):
        self.s.headers.update(header)

    def unset_header(self, key):
        if key in self.s.headers:
            del self.s.headers[key]

    def test(self, name, description, method, url, headers, payload, expected_codes, expected_headers,
             expected_payload, store_file=None):
        """
        Performs an http request and check http code response. Exit if different than allowed. It get the returned id
        that can be used by following test in the URL with {name} where name is the name of the test
        :param name:  short name of the test
        :param description:  description of the test
        :param method: HTTP method: GET,PUT,POST,DELETE,...
        :param url: complete URL or relative URL
        :param headers: request headers to add to the base headers
        :param payload: Can be a dict, transformed to json, a text or a file if starts with '@'
        :param expected_codes: expected response codes, can be int, int tuple or int range
        :param expected_headers: expected response headers, dict with key values
        :param expected_payload: expected payload, 0 if empty, 'yaml', 'json', 'text', 'zip', 'octet-stream'
        :param store_file: filename to store content
        :return: requests response
        """
        r = None
        try:
            if not self.s:
                self.s = requests.session()
            # URL
            if not url:
                url = self.url_base
            elif not url.startswith("http"):
                url = self.url_base + url

            var_start = url.find("<") + 1
            while var_start:
                var_end = url.find(">", var_start)
                if var_end == -1:
                    break
                var_name = url[var_start:var_end]
                if var_name in self.test_ids:
                    url = url[:var_start-1] + self.test_ids[var_name] + url[var_end+1:]
                    var_start += len(self.test_ids[var_name])
                var_start = url.find("<", var_start) + 1
            if payload:
                if isinstance(payload, str):
                    if payload.startswith("@"):
                        mode = "r"
                        file_name = payload[1:]
                        if payload.startswith("@b"):
                            mode = "rb"
                            file_name = payload[2:]
                        with open(file_name, mode) as f:
                            payload = f.read()
                elif isinstance(payload, dict):
                    payload = json.dumps(payload)

            test_description = "Test {} {} {} {}".format(name, description, method, url)
            if self.old_test_description != test_description:
                self.old_test_description = test_description
                logger.warning(test_description)
            stream = False
            if expected_payload in ("zip", "octet-string") or store_file:
                stream = True
            r = getattr(self.s, method.lower())(url, data=payload, headers=headers, verify=self.verify, stream=stream)
            if expected_payload in ("zip", "octet-string") or store_file:
                logger.debug("RX {}".format(r.status_code))
            else:
                logger.debug("RX {}: {}".format(r.status_code, r.text))

            # check response
            if expected_codes:
                if isinstance(expected_codes, int):
                    expected_codes = (expected_codes,)
                if r.status_code not in expected_codes:
                    raise TestException(
                        "Got status {}. Expected {}. {}".format(r.status_code, expected_codes, r.text))

            if expected_headers:
                for header_key, header_val in expected_headers.items():
                    if header_key.lower() not in r.headers:
                        raise TestException("Header {} not present".format(header_key))
                    if header_val and header_val.lower() not in r.headers[header_key]:
                        raise TestException("Header {} does not contain {} but {}".format(header_key, header_val,
                                            r.headers[header_key]))

            if expected_payload is not None:
                if expected_payload == 0 and len(r.content) > 0:
                    raise TestException("Expected empty payload")
                elif expected_payload == "json":
                    try:
                        r.json()
                    except Exception as e:
                        raise TestException("Expected json response payload, but got Exception {}".format(e))
                elif expected_payload == "yaml":
                    try:
                        yaml.safe_load(r.text)
                    except Exception as e:
                        raise TestException("Expected yaml response payload, but got Exception {}".format(e))
                elif expected_payload in ("zip", "octet-string"):
                    if len(r.content) == 0:
                        raise TestException("Expected some response payload, but got empty")
                    # try:
                    #     tar = tarfile.open(None, 'r:gz', fileobj=r.raw)
                    #     for tarinfo in tar:
                    #         tarname = tarinfo.name
                    #         print(tarname)
                    # except Exception as e:
                    #     raise TestException("Expected zip response payload, but got Exception {}".format(e))
                elif expected_payload == "text":
                    if len(r.content) == 0:
                        raise TestException("Expected some response payload, but got empty")
                    # r.text
            if store_file:
                with open(store_file, 'wb') as fd:
                    for chunk in r.iter_content(chunk_size=128):
                        fd.write(chunk)

            location = r.headers.get("Location")
            if location:
                _id = location[location.rfind("/") + 1:]
                if _id:
                    self.test_ids[name] = str(_id)
                    self.test_ids[""] = str(_id)  # last id
            return r
        except TestException as e:
            r_status_code = None
            r_text = None
            if r:
                r_status_code = r.status_code
                r_text = r.text
            logger.error("{} \nRX code{}: {}".format(e, r_status_code, r_text))
            exit(1)
        except IOError as e:
            logger.error("Cannot open file {}".format(e))
            exit(1)

    def get_autorization(self):  # user=None, password=None, project=None):
        if self.token:  # and self.user == user and self.password == password and self.project == project:
            return
        # self.user = user
        # self.password = password
        # self.project = project
        r = self.test("TOKEN", "Obtain token", "POST", "/admin/v1/tokens", headers_json,
                      {"username": self.user, "password": self.password, "project_id": self.project},
                      (200, 201), r_header_json, "json")
        response = r.json()
        self.token = response["id"]
        self.set_header({"Authorization": "Bearer {}".format(self.token)})

    def remove_authorization(self):
        if self.token:
            self.test("TOKEN_DEL", "Delete token", "DELETE", "/admin/v1/tokens/{}".format(self.token), headers_json,
                      None, (200, 201, 204), None, None)
        self.token = None
        self.unset_header("Authorization")

    def get_create_vim(self, test_osm):
        if self.vim_id:
            return self.vim_id
        self.get_autorization()
        if test_osm:
            vim_name = os.environ.get("OSMNBITEST_VIM_NAME")
            if not vim_name:
                raise TestException(
                    "Needed to define OSMNBITEST_VIM_XXX variables to create a real VIM for deployment")
        else:
            vim_name = "fakeVim"
        # Get VIM
        r = self.test("_VIMGET1", "Get VIM ID", "GET", "/admin/v1/vim_accounts?name={}".format(vim_name), headers_json,
                      None, 200, r_header_json, "json")
        vims = r.json()
        if vims:
            return vims[0]["_id"]
        # Add VIM
        if test_osm:
            # check needed environ parameters:
            if not os.environ.get("OSMNBITEST_VIM_URL") or not os.environ.get("OSMNBITEST_VIM_TENANT"):
                raise TestException("Env OSMNBITEST_VIM_URL and OSMNBITEST_VIM_TENANT are needed for create a real VIM"
                                    " to deploy on whit the --test-osm option")
            vim_data = "{{schema_version: '1.0', name: '{}', vim_type: {}, vim_url: '{}', vim_tenant_name: '{}', "\
                       "vim_user: {}, vim_password: {}".format(vim_name,
                                                               os.environ.get("OSMNBITEST_VIM_TYPE", "openstack"),
                                                               os.environ.get("OSMNBITEST_VIM_URL"),
                                                               os.environ.get("OSMNBITEST_VIM_TENANT"),
                                                               os.environ.get("OSMNBITEST_VIM_USER"),
                                                               os.environ.get("OSMNBITEST_VIM_PASSWORD"))
            if os.environ.get("OSMNBITEST_VIM_CONFIG"):
                vim_data += " ,config: {}".format(os.environ.get("OSMNBITEST_VIM_CONFIG"))
            vim_data += "}"
        else:
            vim_data = "{schema_version: '1.0', name: fakeVim, vim_type: openstack, vim_url: 'http://10.11.12.13/fake'"\
                       ", vim_tenant_name: 'vimtenant', vim_user: vimuser, vim_password: vimpassword}"
        r = self.test("_VIMGET2", "Create VIM", "POST", "/admin/v1/vim_accounts", headers_yaml, vim_data,
                      (201), {"Location": "/admin/v1/vim_accounts/", "Content-Type": "application/yaml"}, "yaml")
        location = r.headers.get("Location")
        return location[location.rfind("/") + 1:]


class TestNonAuthorized:
    description = "test invalid URLs. methods and no authorization"

    @staticmethod
    def run(engine, test_osm, manual_check, test_params=None):
        engine.remove_authorization()
        test_not_authorized_list = (
            ("NA1", "Invalid token", "GET", "/admin/v1/users", headers_json, None, 401, r_header_json, "json"),
            ("NA2", "Invalid URL", "POST", "/admin/v1/nonexist", headers_yaml, None, 405, r_header_yaml, "yaml"),
            ("NA3", "Invalid version", "DELETE", "/admin/v2/users", headers_yaml, None, 405, r_header_yaml, "yaml"),
        )
        for t in test_not_authorized_list:
            engine.test(*t)


class TestUsersProjects:
    description = "test project and user creation"

    @staticmethod
    def run(engine, test_osm, manual_check, test_params=None):
        engine.get_autorization()
        engine.test("PU1", "Create project non admin", "POST", "/admin/v1/projects", headers_json, {"name": "P1"},
                    (201, 204), {"Location": "/admin/v1/projects/", "Content-Type": "application/json"}, "json")
        engine.test("PU2", "Create project admin", "POST", "/admin/v1/projects", headers_json,
                    {"name": "Padmin", "admin": True}, (201, 204),
                    {"Location": "/admin/v1/projects/", "Content-Type": "application/json"}, "json")
        engine.test("PU3", "Create project bad format", "POST", "/admin/v1/projects", headers_json, {"name": 1}, 422,
                    r_header_json, "json")
        engine.test("PU4", "Create user with bad project", "POST", "/admin/v1/users", headers_json,
                    {"username": "U1", "projects": ["P1", "P2", "Padmin"], "password": "pw1"}, 409,
                    r_header_json, "json")
        engine.test("PU5", "Create user with bad project and force", "POST", "/admin/v1/users?FORCE=True", headers_json,
                    {"username": "U1", "projects": ["P1", "P2", "Padmin"], "password": "pw1"}, 201,
                    {"Location": "/admin/v1/users/", "Content-Type": "application/json"}, "json")
        engine.test("PU6", "Create user 2", "POST", "/admin/v1/users", headers_json,
                    {"username": "U2", "projects": ["P1"], "password": "pw2"}, 201,
                    {"Location": "/admin/v1/users/", "Content-Type": "application/json"}, "json")

        engine.test("PU7", "Edit user U1, delete  P2 project", "PATCH", "/admin/v1/users/U1", headers_json,
                    {"projects": {"$'P2'": None}}, 204, None, None)
        res = engine.test("PU1", "Check user U1, contains the right projects", "GET", "/admin/v1/users/U1",
                          headers_json, None, 200, None, json)
        u1 = res.json()
        # print(u1)
        expected_projects = ["P1", "Padmin"]
        if u1["projects"] != expected_projects:
            raise TestException("User content projects '{}' different than expected '{}'. Edition has not done"
                                " properly".format(u1["projects"], expected_projects))

        engine.test("PU8", "Edit user U1, set Padmin as default project", "PUT", "/admin/v1/users/U1", headers_json,
                    {"projects": {"$'Padmin'": None, "$+[0]": "Padmin"}}, 204, None, None)
        res = engine.test("PU1", "Check user U1, contains the right projects", "GET", "/admin/v1/users/U1",
                          headers_json, None, 200, None, json)
        u1 = res.json()
        # print(u1)
        expected_projects = ["Padmin", "P1"]
        if u1["projects"] != expected_projects:
            raise TestException("User content projects '{}' different than expected '{}'. Edition has not done"
                                " properly".format(u1["projects"], expected_projects))

        engine.test("PU9", "Edit user U1, change password", "PATCH", "/admin/v1/users/U1", headers_json,
                    {"password": "pw1_new"}, 204, None, None)

        engine.test("PU10", "Change to project P1 non existing", "POST", "/admin/v1/tokens/", headers_json,
                    {"project_id": "P1"}, 401, r_header_json, "json")

        res = engine.test("PU1", "Change to user U1 project P1", "POST", "/admin/v1/tokens", headers_json,
                          {"username": "U1", "password": "pw1_new", "project_id": "P1"}, (200, 201),
                          r_header_json, "json")
        response = res.json()
        engine.set_header({"Authorization": "Bearer {}".format(response["id"])})

        engine.test("PU11", "Edit user projects non admin", "PUT", "/admin/v1/users/U1", headers_json,
                    {"projects": {"$'P1'": None}}, 401, r_header_json, "json")
        engine.test("PU12", "Add new project non admin", "POST", "/admin/v1/projects", headers_json,
                    {"name": "P2"}, 401, r_header_json, "json")
        engine.test("PU13", "Add new user non admin", "POST", "/admin/v1/users", headers_json,
                    {"username": "U3", "projects": ["P1"], "password": "pw3"}, 401,
                    r_header_json, "json")

        res = engine.test("PU14", "Change to user U1 project Padmin", "POST", "/admin/v1/tokens", headers_json,
                          {"project_id": "Padmin"}, (200, 201), r_header_json, "json")
        response = res.json()
        engine.set_header({"Authorization": "Bearer {}".format(response["id"])})

        engine.test("PU15", "Add new project admin", "POST", "/admin/v1/projects", headers_json, {"name": "P2"},
                    (201, 204), {"Location": "/admin/v1/projects/", "Content-Type": "application/json"}, "json")
        engine.test("PU16", "Add new user U3 admin", "POST", "/admin/v1/users",
                    headers_json, {"username": "U3", "projects": ["P2"], "password": "pw3"}, (201, 204),
                    {"Location": "/admin/v1/users/", "Content-Type": "application/json"}, "json")
        engine.test("PU17", "Edit user projects admin", "PUT", "/admin/v1/users/U3", headers_json,
                    {"projects": ["P2"]}, 204, None, None)

        engine.test("PU18", "Delete project P2 conflict", "DELETE", "/admin/v1/projects/P2", headers_json, None, 409,
                    r_header_json, "json")
        engine.test("PU19", "Delete project P2 forcing", "DELETE", "/admin/v1/projects/P2?FORCE=True", headers_json,
                    None, 204, None, None)

        engine.test("PU20", "Delete user U1. Conflict deleting own user", "DELETE", "/admin/v1/users/U1", headers_json,
                    None, 409, r_header_json, "json")
        engine.test("PU21", "Delete user U2", "DELETE", "/admin/v1/users/U2", headers_json, None, 204, None, None)
        engine.test("PU22", "Delete user U3", "DELETE", "/admin/v1/users/U3", headers_json, None, 204, None, None)
        # change to admin
        engine.remove_authorization()   # To force get authorization
        engine.get_autorization()
        engine.test("PU23", "Delete user U1", "DELETE", "/admin/v1/users/U1", headers_json, None, 204, None, None)
        engine.test("PU24", "Delete project P1", "DELETE", "/admin/v1/projects/P1", headers_json, None, 204, None, None)
        engine.test("PU25", "Delete project Padmin", "DELETE", "/admin/v1/projects/Padmin", headers_json, None, 204,
                    None, None)


class TestFakeVim:
    description = "Creates/edit/delete fake VIMs and SDN controllers"

    def __init__(self):
        self.vim = {
            "schema_version": "1.0",
            "schema_type": "No idea",
            "name": "myVim",
            "description": "Descriptor name",
            "vim_type": "openstack",
            "vim_url": "http://localhost:/vim",
            "vim_tenant_name": "vimTenant",
            "vim_user": "user",
            "vim_password": "password",
            "config": {"config_param": 1}
        }
        self.sdn = {
            "name": "sdn-name",
            "description": "sdn-description",
            "dpid": "50:50:52:54:00:94:21:21",
            "ip": "192.168.15.17",
            "port": 8080,
            "type": "opendaylight",
            "version": "3.5.6",
            "user": "user",
            "password": "passwd"
        }
        self.port_mapping = [
            {"compute_node": "compute node 1",
             "ports": [{"pci": "0000:81:00.0", "switch_port": "port-2/1", "switch_mac": "52:54:00:94:21:21"},
                       {"pci": "0000:81:00.1", "switch_port": "port-2/2", "switch_mac": "52:54:00:94:21:22"}
                       ]},
            {"compute_node": "compute node 2",
             "ports": [{"pci": "0000:81:00.0", "switch_port": "port-2/3", "switch_mac": "52:54:00:94:21:23"},
                       {"pci": "0000:81:00.1", "switch_port": "port-2/4", "switch_mac": "52:54:00:94:21:24"}
                       ]}
        ]

    def run(self, engine, test_osm, manual_check, test_params=None):

        vim_bad = self.vim.copy()
        vim_bad.pop("name")

        engine.get_autorization()
        engine.test("FVIM1", "Create VIM", "POST", "/admin/v1/vim_accounts", headers_json, self.vim, (201, 204),
                    {"Location": "/admin/v1/vim_accounts/", "Content-Type": "application/json"}, "json")
        engine.test("FVIM2", "Create VIM without name, bad schema", "POST", "/admin/v1/vim_accounts", headers_json,
                    vim_bad, 422, None, headers_json)
        engine.test("FVIM3", "Create VIM name repeated", "POST", "/admin/v1/vim_accounts", headers_json, self.vim,
                    409, None, headers_json)
        engine.test("FVIM4", "Show VIMs", "GET", "/admin/v1/vim_accounts", headers_yaml, None, 200, r_header_yaml,
                    "yaml")
        engine.test("FVIM5", "Show VIM", "GET", "/admin/v1/vim_accounts/<FVIM1>", headers_yaml, None, 200,
                    r_header_yaml, "yaml")
        if not test_osm:
            # delete with FORCE
            engine.test("FVIM6", "Delete VIM", "DELETE", "/admin/v1/vim_accounts/<FVIM1>?FORCE=True", headers_yaml,
                        None, 202, None, 0)
            engine.test("FVIM7", "Check VIM is deleted", "GET", "/admin/v1/vim_accounts/<FVIM1>", headers_yaml, None,
                        404, r_header_yaml, "yaml")
        else:
            # delete and wait until is really deleted
            engine.test("FVIM6", "Delete VIM", "DELETE", "/admin/v1/vim_accounts/<FVIM1>", headers_yaml, None, 202,
                        None, 0)
            wait = timeout
            while wait >= 0:
                r = engine.test("FVIM7", "Check VIM is deleted", "GET", "/admin/v1/vim_accounts/<FVIM1>", headers_yaml,
                                None, None, r_header_yaml, "yaml")
                if r.status_code == 404:
                    break
                elif r.status_code == 200:
                    wait -= 5
                    sleep(5)
            else:
                raise TestException("Vim created at 'FVIM1' is not delete after {} seconds".format(timeout))


class TestVIMSDN(TestFakeVim):
    description = "Creates VIM with SDN editing SDN controllers and port_mapping"

    def __init__(self):
        TestFakeVim.__init__(self)

    def run(self, engine, test_osm, manual_check, test_params=None):
        engine.get_autorization()
        # Added SDN
        engine.test("VIMSDN1", "Create SDN", "POST", "/admin/v1/sdns", headers_json, self.sdn, (201, 204),
                    {"Location": "/admin/v1/sdns/", "Content-Type": "application/json"}, "json")
        # sleep(5)
        # Edit SDN
        engine.test("VIMSDN2", "Edit SDN", "PATCH", "/admin/v1/sdns/<VIMSDN1>", headers_json, {"name": "new_sdn_name"},
                    204, None, None)
        # sleep(5)
        # VIM with SDN
        self.vim["config"]["sdn-controller"] = engine.test_ids["VIMSDN1"]
        self.vim["config"]["sdn-port-mapping"] = self.port_mapping
        engine.test("VIMSDN3", "Create VIM", "POST", "/admin/v1/vim_accounts", headers_json, self.vim, (200, 204, 201),
                    {"Location": "/admin/v1/vim_accounts/", "Content-Type": "application/json"}, "json"),

        self.port_mapping[0]["compute_node"] = "compute node XX"
        engine.test("VIMSDN4", "Edit VIM change port-mapping", "PUT", "/admin/v1/vim_accounts/<VIMSDN3>", headers_json,
                    {"config": {"sdn-port-mapping": self.port_mapping}}, 204, None, None)
        engine.test("VIMSDN5", "Edit VIM remove port-mapping", "PUT", "/admin/v1/vim_accounts/<VIMSDN3>", headers_json,
                    {"config": {"sdn-port-mapping": None}}, 204, None, None)

        if not test_osm:
            # delete with FORCE
            engine.test("VIMSDN6", "Delete VIM remove port-mapping", "DELETE",
                        "/admin/v1/vim_accounts/<VIMSDN3>?FORCE=True", headers_json, None, 202, None, 0)
            engine.test("VIMSDN7", "Delete SDNC", "DELETE", "/admin/v1/sdns/<VIMSDN1>?FORCE=True", headers_json, None,
                        202, None, 0)

            engine.test("VIMSDN8", "Check VIM is deleted", "GET", "/admin/v1/vim_accounts/<VIMSDN3>", headers_yaml,
                        None, 404, r_header_yaml, "yaml")
            engine.test("VIMSDN9", "Check SDN is deleted", "GET", "/admin/v1/sdns/<VIMSDN1>", headers_yaml, None,
                        404, r_header_yaml, "yaml")
        else:
            # delete and wait until is really deleted
            engine.test("VIMSDN6", "Delete VIM remove port-mapping", "DELETE", "/admin/v1/vim_accounts/<VIMSDN3>",
                        headers_json, None, (202, 201, 204), None, 0)
            engine.test("VIMSDN7", "Delete SDN", "DELETE", "/admin/v1/sdns/<VIMSDN1>", headers_json, None,
                        (202, 201, 204), None, 0)
            wait = timeout
            while wait >= 0:
                r = engine.test("VIMSDN8", "Check VIM is deleted", "GET", "/admin/v1/vim_accounts/<VIMSDN3>",
                                headers_yaml, None, None, r_header_yaml, "yaml")
                if r.status_code == 404:
                    break
                elif r.status_code == 200:
                    wait -= 5
                    sleep(5)
            else:
                raise TestException("Vim created at 'VIMSDN3' is not delete after {} seconds".format(timeout))
            while wait >= 0:
                r = engine.test("VIMSDN9", "Check SDNC is deleted", "GET", "/admin/v1/sdns/<VIMSDN1>",
                                headers_yaml, None, None, r_header_yaml, "yaml")
                if r.status_code == 404:
                    break
                elif r.status_code == 200:
                    wait -= 5
                    sleep(5)
            else:
                raise TestException("SDNC created at 'VIMSDN1' is not delete after {} seconds".format(timeout))


class TestDeploy:
    description = "Base class for downloading descriptors from ETSI, onboard and deploy in real VIM"

    def __init__(self):
        self.step = 0
        self.nsd_id = None
        self.vim_id = None
        self.nsd_test = None
        self.ns_test = None
        self.ns_id = None
        self.vnfds_test = []
        self.vnfds_id = []
        self.descriptor_url = "https://osm-download.etsi.org/ftp/osm-3.0-three/2nd-hackfest/packages/"
        self.vnfd_filenames = ("cirros_vnf.tar.gz",)
        self.nsd_filename = "cirros_2vnf_ns.tar.gz"
        self.uses_configuration = False
        self.uss = {}
        self.passwds = {}
        self.cmds = {}
        self.keys = {}
        self.timeout = 120
        self.passed_tests = 0
        self.total_tests = 0

    def create_descriptors(self, engine):
        temp_dir = os.path.dirname(os.path.abspath(__file__)) + "/temp/"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        for vnfd_filename in self.vnfd_filenames:
            if "/" in vnfd_filename:
                vnfd_filename_path = vnfd_filename
                if not os.path.exists(vnfd_filename_path):
                    raise TestException("File '{}' does not exist".format(vnfd_filename_path))
            else:
                vnfd_filename_path = temp_dir + vnfd_filename
                if not os.path.exists(vnfd_filename_path):
                    with open(vnfd_filename_path, "wb") as file:
                        response = requests.get(self.descriptor_url + vnfd_filename)
                        if response.status_code >= 300:
                            raise TestException("Error downloading descriptor from '{}': {}".format(
                                self.descriptor_url + vnfd_filename, response.status_code))
                        file.write(response.content)
            if vnfd_filename_path.endswith(".yaml"):
                headers = headers_yaml
            else:
                headers = headers_zip_yaml
            if self.step % 2 == 0:
                # vnfd CREATE AND UPLOAD in one step:
                test_name = "DEPLOY{}".format(self.step)
                engine.test(test_name, "Onboard VNFD in one step", "POST",
                            "/vnfpkgm/v1/vnf_packages_content", headers, "@b" + vnfd_filename_path, 201,
                            {"Location": "/vnfpkgm/v1/vnf_packages_content/", "Content-Type": "application/yaml"}, yaml)
                self.vnfds_test.append(test_name)
                self.vnfds_id.append(engine.test_ids[test_name])
                self.step += 1
            else:
                # vnfd CREATE AND UPLOAD ZIP
                test_name = "DEPLOY{}".format(self.step)
                engine.test(test_name, "Onboard VNFD step 1", "POST", "/vnfpkgm/v1/vnf_packages",
                            headers_json, None, 201,
                            {"Location": "/vnfpkgm/v1/vnf_packages/", "Content-Type": "application/json"}, "json")
                self.vnfds_test.append(test_name)
                self.vnfds_id.append(engine.test_ids[test_name])
                self.step += 1
                # location = r.headers["Location"]
                # vnfd_id = location[location.rfind("/")+1:]
                engine.test("DEPLOY{}".format(self.step), "Onboard VNFD step 2 as ZIP", "PUT",
                            "/vnfpkgm/v1/vnf_packages/<>/package_content",
                            headers, "@b" + vnfd_filename_path, 204, None, 0)
                self.step += 2

        if "/" in self.nsd_filename:
            nsd_filename_path = self.nsd_filename
            if not os.path.exists(nsd_filename_path):
                raise TestException("File '{}' does not exist".format(nsd_filename_path))
        else:
            nsd_filename_path = temp_dir + self.nsd_filename
            if not os.path.exists(nsd_filename_path):
                with open(nsd_filename_path, "wb") as file:
                    response = requests.get(self.descriptor_url + self.nsd_filename)
                    if response.status_code >= 300:
                        raise TestException("Error downloading descriptor from '{}': {}".format(
                            self.descriptor_url + self.nsd_filename, response.status_code))
                    file.write(response.content)
        if nsd_filename_path.endswith(".yaml"):
            headers = headers_yaml
        else:
            headers = headers_zip_yaml

        self.nsd_test = "DEPLOY" + str(self.step)
        if self.step % 2 == 0:
            # nsd CREATE AND UPLOAD in one step:
            engine.test("DEPLOY{}".format(self.step), "Onboard NSD in one step", "POST",
                        "/nsd/v1/ns_descriptors_content", headers, "@b" + nsd_filename_path, 201,
                        {"Location": "/nsd/v1/ns_descriptors_content/", "Content-Type": "application/yaml"}, yaml)
            self.step += 1
        else:
            # nsd CREATE AND UPLOAD ZIP
            engine.test("DEPLOY{}".format(self.step), "Onboard NSD step 1", "POST", "/nsd/v1/ns_descriptors",
                        headers_json, None, 201,
                        {"Location": "/nsd/v1/ns_descriptors/", "Content-Type": "application/json"}, "json")
            self.step += 1
            # location = r.headers["Location"]
            # vnfd_id = location[location.rfind("/")+1:]
            engine.test("DEPLOY{}".format(self.step), "Onboard NSD step 2 as ZIP", "PUT",
                        "/nsd/v1/ns_descriptors/<>/nsd_content",
                        headers, "@b" + nsd_filename_path, 204, None, 0)
            self.step += 2
        self.nsd_id = engine.test_ids[self.nsd_test]

    def delete_descriptors(self, engine):
        # delete descriptors
        engine.test("DEPLOY{}".format(self.step), "Delete NSSD SOL005", "DELETE",
                    "/nsd/v1/ns_descriptors/<{}>".format(self.nsd_test),
                    headers_yaml, None, 204, None, 0)
        self.step += 1
        for vnfd_test in self.vnfds_test:
            engine.test("DEPLOY{}".format(self.step), "Delete VNFD SOL005", "DELETE",
                        "/vnfpkgm/v1/vnf_packages/<{}>".format(vnfd_test), headers_yaml, None, 204, None, 0)
            self.step += 1

    def instantiate(self, engine, ns_data):
        ns_data_text = yaml.safe_dump(ns_data, default_flow_style=True, width=256)
        # create NS Two steps
        r = engine.test("DEPLOY{}".format(self.step), "Create NS step 1", "POST", "/nslcm/v1/ns_instances",
                        headers_yaml, ns_data_text, 201,
                        {"Location": "nslcm/v1/ns_instances/", "Content-Type": "application/yaml"}, "yaml")
        self.ns_test = "DEPLOY{}".format(self.step)
        self.ns_id = engine.test_ids[self.ns_test]
        engine.test_ids[self.ns_test]
        self.step += 1
        r = engine.test("DEPLOY{}".format(self.step), "Instantiate NS step 2", "POST",
                        "/nslcm/v1/ns_instances/<{}>/instantiate".format(self.ns_test), headers_yaml, ns_data_text,
                        201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
        nslcmop_test = "DEPLOY{}".format(self.step)
        self.step += 1

        if test_osm:
            # Wait until status is Ok
            wait = timeout_configure if self.uses_configuration else timeout_deploy
            while wait >= 0:
                r = engine.test("DEPLOY{}".format(self.step), "Wait until NS is deployed and configured", "GET",
                                "/nslcm/v1/ns_lcm_op_occs/<{}>".format(nslcmop_test), headers_json, None,
                                200, r_header_json, "json")
                nslcmop = r.json()
                if "COMPLETED" in nslcmop["operationState"]:
                    break
                elif "FAILED" in nslcmop["operationState"]:
                    raise TestException("NS instantiate has failed: {}".format(nslcmop["detailed-status"]))
                wait -= 5
                sleep(5)
            else:
                raise TestException("NS instantiate is not done after {} seconds".format(timeout_deploy))
            self.step += 1

    def _wait_nslcmop_ready(self, engine, nslcmop_test, timeout_deploy, expected_fail=False):
        wait = timeout
        while wait >= 0:
            r = engine.test("DEPLOY{}".format(self.step), "Wait to ns lcm operation complete", "GET",
                            "/nslcm/v1/ns_lcm_op_occs/<{}>".format(nslcmop_test), headers_json, None,
                            200, r_header_json, "json")
            nslcmop = r.json()
            if "COMPLETED" in nslcmop["operationState"]:
                if expected_fail:
                    raise TestException("NS terminate has success, expecting failing: {}".format(
                        nslcmop["detailed-status"]))
                break
            elif "FAILED" in nslcmop["operationState"]:
                if not expected_fail:
                    raise TestException("NS terminate has failed: {}".format(nslcmop["detailed-status"]))
                break
            wait -= 5
            sleep(5)
        else:
            raise TestException("NS instantiate is not terminate after {} seconds".format(timeout))

    def terminate(self, engine):
        # remove deployment
        if test_osm:
            r = engine.test("DEPLOY{}".format(self.step), "Terminate NS", "POST",
                            "/nslcm/v1/ns_instances/<{}>/terminate".format(self.ns_test), headers_yaml, None,
                            201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
            nslcmop2_test = "DEPLOY{}".format(self.step)
            self.step += 1
            # Wait until status is Ok
            self._wait_nslcmop_ready(engine, nslcmop2_test, timeout_deploy)

            r = engine.test("DEPLOY{}".format(self.step), "Delete NS", "DELETE",
                            "/nslcm/v1/ns_instances/<{}>".format(self.ns_test), headers_yaml, None,
                            204, None, 0)
            self.step += 1
        else:
            r = engine.test("DEPLOY{}".format(self.step), "Delete NS with FORCE", "DELETE",
                            "/nslcm/v1/ns_instances/<{}>?FORCE=True".format(self.ns_test), headers_yaml, None,
                            204, None, 0)
            self.step += 1

        # check all it is deleted
        r = engine.test("DEPLOY{}".format(self.step), "Check NS is deleted", "GET",
                        "/nslcm/v1/ns_instances/<{}>".format(self.ns_test), headers_yaml, None,
                        404, None, "yaml")
        self.step += 1
        r = engine.test("DEPLOY{}".format(self.step), "Check NSLCMOPs are deleted", "GET",
                        "/nslcm/v1/ns_lcm_op_occs?nsInstanceId=<{}>".format(self.ns_test), headers_json, None,
                        200, None, "json")
        nslcmops = r.json()
        if not isinstance(nslcmops, list) or nslcmops:
            raise TestException("NS {} deleted but with ns_lcm_op_occ active: {}".format(self.ns_test, nslcmops))

    def test_ns(self, engine, test_osm, commands=None, users=None, passwds=None, keys=None, timeout=0):

        n = 0
        r = engine.test("TEST_NS{}".format(n), "GET VNFR_IDs", "GET",
                        "/nslcm/v1/ns_instances/{}".format(self.ns_id), headers_json, None,
                        200, r_header_json, "json")
        n += 1
        ns_data = r.json()

        vnfr_list = ns_data['constituent-vnfr-ref']
        time = 0

        for vnfr_id in vnfr_list:
            self.total_tests += 1
            r = engine.test("TEST_NS{}".format(n), "GET IP_ADDRESS OF VNFR", "GET",
                            "/nslcm/v1/vnfrs/{}".format(vnfr_id), headers_json, None,
                            200, r_header_json, "json")
            n += 1
            vnfr_data = r.json()

            if vnfr_data.get("ip-address"):
                name = "TEST_NS{}".format(n)
                description = "Run tests in VNFR with IP {}".format(vnfr_data['ip-address'])
                n += 1
                test_description = "Test {} {}".format(name, description)
                logger.warning(test_description)
                vnf_index = str(vnfr_data["member-vnf-index-ref"])
                while timeout >= time:
                    result, message = self.do_checks([vnfr_data["ip-address"]],
                                                     vnf_index=vnfr_data["member-vnf-index-ref"],
                                                     commands=commands.get(vnf_index), user=users.get(vnf_index),
                                                     passwd=passwds.get(vnf_index), key=keys.get(vnf_index))
                    if result == 1:
                        logger.warning(message)
                        break
                    elif result == 0:
                        time += 20
                        sleep(20)
                    elif result == -1:
                        logger.critical(message)
                        break
                else:
                    time -= 20
                    logger.critical(message)
            else:
                logger.critical("VNFR {} has not mgmt address. Check failed".format(vnfr_id))

    def do_checks(self, ip, vnf_index, commands=[], user=None, passwd=None, key=None):
        try:
            import urllib3
            from pssh.clients import ParallelSSHClient
            from pssh.utils import load_private_key
            from ssh2 import exceptions as ssh2Exception
        except ImportError as e:
            logger.critical("package <pssh> or/and <urllib3> is not installed. Please add it with 'pip3 install "
                            "parallel-ssh' and/or 'pip3 install urllib3': {}".format(e))
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            p_host = os.environ.get("PROXY_HOST")
            p_user = os.environ.get("PROXY_USER")
            p_password = os.environ.get("PROXY_PASSWD")

            if key:
                pkey = load_private_key(key)
            else:
                pkey = None

            client = ParallelSSHClient(ip, user=user, password=passwd, pkey=pkey, proxy_host=p_host,
                                       proxy_user=p_user, proxy_password=p_password, timeout=10, num_retries=0)
            for cmd in commands:
                output = client.run_command(cmd)
                client.join(output)
                if output[ip[0]].exit_code:
                    return -1, "    VNFR {} could not be checked: {}".format(ip[0], output[ip[0]].stderr)
                else:
                    self.passed_tests += 1
                    return 1, "    Test successful"
        except (ssh2Exception.ChannelFailure, ssh2Exception.SocketDisconnectError, ssh2Exception.SocketTimeout,
                ssh2Exception.SocketRecvError) as e:
            return 0, "Timeout accessing the VNFR {}: {}".format(ip[0], str(e))
        except Exception as e:
            return -1, "ERROR checking the VNFR {}: {}".format(ip[0], str(e))

    def aditional_operations(self, engine, test_osm, manual_check):
        pass

    def run(self, engine, test_osm, manual_check, test_params=None):
        engine.get_autorization()
        nsname = os.environ.get("OSMNBITEST_NS_NAME", "OSMNBITEST")
        if test_params:
            if "vnfd-files" in test_params:
                self.vnfd_filenames = test_params["vnfd-files"].split(",")
            if "nsd-file" in test_params:
                self.nsd_filename = test_params["nsd-file"]
            if test_params.get("ns-name"):
                nsname = test_params["ns-name"]
        self.create_descriptors(engine)

        # create real VIM if not exist
        self.vim_id = engine.get_create_vim(test_osm)
        ns_data = {"nsDescription": "default description", "nsName": nsname, "nsdId": self.nsd_id,
                   "vimAccountId": self.vim_id}
        if test_params and test_params.get("ns-config"):
            if isinstance(test_params["ns-config"], str):
                ns_data.update(yaml.load(test_params["ns-config"]))
            else:
                ns_data.update(test_params["ns-config"])
        self.instantiate(engine, ns_data)

        if manual_check:
            input('NS has been deployed. Perform manual check and press enter to resume')
        else:
            self.test_ns(engine, test_osm, self.cmds, self.uss, self.pss, self.keys, self.timeout)
        self.aditional_operations(engine, test_osm, manual_check)
        self.terminate(engine)
        self.delete_descriptors(engine)
        self.print_results()

    def print_results(self):
        print("\n\n\n--------------------------------------------")
        print("TEST RESULTS:\n PASSED TESTS: {} - TOTAL TESTS: {}".format(self.total_tests, self.passed_tests))
        print("--------------------------------------------")


class TestDeployHackfestCirros(TestDeploy):
    description = "Load and deploy Hackfest cirros_2vnf_ns example"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("cirros_vnf.tar.gz",)
        self.nsd_filename = "cirros_2vnf_ns.tar.gz"
        self.cmds = {'1': ['ls -lrt', ], '2': ['ls -lrt', ]}
        self.uss = {'1': "cirros", '2': "cirros"}
        self.pss = {'1': "cubswin:)", '2': "cubswin:)"}


class TestDeployHackfest1(TestDeploy):
    description = "Load and deploy Hackfest_1_vnfd example"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("hackfest_1_vnfd.tar.gz",)
        self.nsd_filename = "hackfest_1_nsd.tar.gz"
        # self.cmds = {'1': ['ls -lrt', ], '2': ['ls -lrt', ]}
        # self.uss = {'1': "cirros", '2': "cirros"}
        # self.pss = {'1': "cubswin:)", '2': "cubswin:)"}


class TestDeployHackfestCirrosScaling(TestDeploy):
    description = "Load and deploy Hackfest cirros_2vnf_ns example with scaling modifications"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("cirros_vnf.tar.gz",)
        self.nsd_filename = "cirros_2vnf_ns.tar.gz"

    def create_descriptors(self, engine):
        super().create_descriptors(engine)
        # Modify VNFD to add scaling and count=2
        payload = """
            vdu: 
                "$id: 'cirros_vnfd-VM'":
                    count: 2
            scaling-group-descriptor:
                -   name: "scale_cirros"
                    max-instance-count: 2
                    vdu:
                    -   vdu-id-ref: cirros_vnfd-VM
                        count: 2
        """
        engine.test("DEPLOY{}".format(self.step), "Edit VNFD ", "PATCH",
                    "/vnfpkgm/v1/vnf_packages/{}".format(self.vnfds_id[0]),
                    headers_yaml, payload, 204, None, None)
        self.step += 1

    def aditional_operations(self, engine, test_osm, manual_check):
        if not test_osm:
            return
        # 2 perform scale out twice
        payload = '{scaleType: SCALE_VNF, scaleVnfData: {scaleVnfType: SCALE_OUT, scaleByStepData: ' \
                  '{scaling-group-descriptor: scale_cirros, member-vnf-index: "1"}}}'
        for i in range(0, 2):
            engine.test("DEPLOY{}".format(self.step), "Execute scale action over NS", "POST",
                        "/nslcm/v1/ns_instances/<{}>/scale".format(self.ns_test), headers_yaml, payload,
                        201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
            nslcmop2_scale_out = "DEPLOY{}".format(self.step)
            self._wait_nslcmop_ready(engine, nslcmop2_scale_out, timeout_deploy)
            if manual_check:
                input('NS scale out done. Check that two more vdus are there')
            # TODO check automatic

        # 2 perform scale in
        payload = '{scaleType: SCALE_VNF, scaleVnfData: {scaleVnfType: SCALE_IN, scaleByStepData: ' \
                  '{scaling-group-descriptor: scale_cirros, member-vnf-index: "1"}}}'
        for i in range(0, 2):
            engine.test("DEPLOY{}".format(self.step), "Execute scale IN action over NS", "POST",
                        "/nslcm/v1/ns_instances/<{}>/scale".format(self.ns_test), headers_yaml, payload,
                        201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
            nslcmop2_scale_in = "DEPLOY{}".format(self.step)
            self._wait_nslcmop_ready(engine, nslcmop2_scale_in, timeout_deploy)
            if manual_check:
                input('NS scale in done. Check that two less vdus are there')
            # TODO check automatic

        # perform scale in that must fail as reached limit
        engine.test("DEPLOY{}".format(self.step), "Execute scale IN out of limit action over NS", "POST",
                    "/nslcm/v1/ns_instances/<{}>/scale".format(self.ns_test), headers_yaml, payload,
                    201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
        nslcmop2_scale_in = "DEPLOY{}".format(self.step)
        self._wait_nslcmop_ready(engine, nslcmop2_scale_in, timeout_deploy, expected_fail=True)


class TestDeployIpMac(TestDeploy):
    description = "Load and deploy descriptor examples setting mac, ip address at descriptor and instantiate params"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("vnfd_2vdu_set_ip_mac2.yaml", "vnfd_2vdu_set_ip_mac.yaml")
        self.nsd_filename = "scenario_2vdu_set_ip_mac.yaml"
        self.descriptor_url = \
            "https://osm.etsi.org/gitweb/?p=osm/RO.git;a=blob_plain;f=test/RO_tests/v3_2vdu_set_ip_mac/"
        self.cmds = {'1': ['ls -lrt', ], '2': ['ls -lrt', ]}
        self.uss = {'1': "osm", '2': "osm"}
        self.pss = {'1': "osm4u", '2': "osm4u"}
        self.timeout = 360

    def run(self, engine, test_osm, manual_check, test_params=None):
        # super().run(engine, test_osm, manual_check, test_params)
        # run again setting IPs with instantiate parameters
        instantiation_params = {
            "vnf": [
                {
                    "member-vnf-index": "1",
                    "internal-vld": [
                        {
                            "name": "internal_vld1",   # net_internal
                            "ip-profile": {
                                "ip-version": "ipv4",
                                "subnet-address": "10.9.8.0/24",
                                "dhcp-params": {"count": 100, "start-address": "10.9.8.100"}
                            },
                            "internal-connection-point": [
                                {
                                    "id-ref": "eth2",
                                    "ip-address": "10.9.8.2",
                                },
                                {
                                    "id-ref": "eth3",
                                    "ip-address": "10.9.8.3",
                                }
                            ]
                        },
                    ],

                    "vdu": [
                        {
                            "id": "VM1",
                            "interface": [
                                # {
                                #     "name": "iface11",
                                #     "floating-ip-required": True,
                                # },
                                {
                                    "name": "iface13",
                                    "mac-address": "52:33:44:55:66:13"
                                },
                            ],
                        },
                        {
                            "id": "VM2",
                            "interface": [
                                {
                                    "name": "iface21",
                                    "ip-address": "10.31.31.22",
                                    "mac-address": "52:33:44:55:66:21"
                                },
                            ],
                        },
                    ]
                },
            ]
        }

        super().run(engine, test_osm, manual_check, test_params={"ns-config": instantiation_params})


class TestDeployHackfest4(TestDeploy):
    description = "Load and deploy Hackfest 4 example."

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("hackfest_4_vnfd.tar.gz",)
        self.nsd_filename = "hackfest_4_nsd.tar.gz"
        self.uses_configuration = True
        self.cmds = {'1': ['ls -lrt', ], '2': ['ls -lrt', ]}
        self.uss = {'1': "ubuntu", '2': "ubuntu"}
        self.pss = {'1': "osm4u", '2': "osm4u"}

    def create_descriptors(self, engine):
        super().create_descriptors(engine)
        # Modify VNFD to add scaling
        payload = """
            scaling-group-descriptor:
                -   name: "scale_dataVM"
                    max-instance-count: 10
                    scaling-policy:
                    -   name: "auto_cpu_util_above_threshold"
                        scaling-type: "automatic"
                        threshold-time: 0
                        cooldown-time: 60
                        scaling-criteria:
                        -   name: "cpu_util_above_threshold"
                            scale-in-threshold: 15
                            scale-in-relational-operation: "LE"
                            scale-out-threshold: 60
                            scale-out-relational-operation: "GE"
                            vnf-monitoring-param-ref: "all_aaa_cpu_util"
                    vdu:
                    -   vdu-id-ref: dataVM
                        count: 1
                    scaling-config-action:
                    -   trigger: post-scale-out
                        vnf-config-primitive-name-ref: touch
                    -   trigger: pre-scale-in
                        vnf-config-primitive-name-ref: touch
            vnf-configuration:
                config-primitive:
                -   name: touch
                    parameter:
                    -   name: filename
                        data-type: STRING
                        default-value: '/home/ubuntu/touched'
        """
        engine.test("DEPLOY{}".format(self.step), "Edit VNFD ", "PATCH",
                    "/vnfpkgm/v1/vnf_packages/<{}>".format(self.vnfds_test[0]), headers_yaml, payload, 204, None, None)
        self.step += 1


class TestDeployHackfest3Charmed(TestDeploy):
    description = "Load and deploy Hackfest 3charmed_ns example. Modifies it for adding scaling and performs " \
                  "primitive actions and scaling"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("hackfest_3charmed_vnfd.tar.gz",)
        self.nsd_filename = "hackfest_3charmed_nsd.tar.gz"
        self.uses_configuration = True
        self.cmds = {'1': [''], '2': ['ls -lrt /home/ubuntu/first-touch', ]}
        self.uss = {'1': "ubuntu", '2': "ubuntu"}
        self.pss = {'1': "osm4u", '2': "osm4u"}

    # def create_descriptors(self, engine):
    #     super().create_descriptors(engine)
    #     # Modify VNFD to add scaling
    #     payload = """
    #         scaling-group-descriptor:
    #             -   name: "scale_dataVM"
    #                 max-instance-count: 10
    #                 scaling-policy:
    #                 -   name: "auto_cpu_util_above_threshold"
    #                     scaling-type: "automatic"
    #                     threshold-time: 0
    #                     cooldown-time: 60
    #                     scaling-criteria:
    #                     -   name: "cpu_util_above_threshold"
    #                         scale-in-threshold: 15
    #                         scale-in-relational-operation: "LE"
    #                         scale-out-threshold: 60
    #                         scale-out-relational-operation: "GE"
    #                         vnf-monitoring-param-ref: "all_aaa_cpu_util"
    #                 vdu:
    #                 -   vdu-id-ref: dataVM
    #                     count: 1
    #                 scaling-config-action:
    #                 -   trigger: post-scale-out
    #                     vnf-config-primitive-name-ref: touch
    #                 -   trigger: pre-scale-in
    #                     vnf-config-primitive-name-ref: touch
    #         vnf-configuration:
    #             config-primitive:
    #             -   name: touch
    #                 parameter:
    #                 -   name: filename
    #                     data-type: STRING
    #                     default-value: '/home/ubuntu/touched'
    #     """
    #     engine.test("DEPLOY{}".format(self.step), "Edit VNFD ", "PATCH",
    #                 "/vnfpkgm/v1/vnf_packages/<{}>".format(self.vnfds_test[0]),
    #                 headers_yaml, payload, 200,
    #                 r_header_yaml, yaml)
    #     self.vnfds_test.append("DEPLOY" + str(self.step))
    #     self.step += 1

    def aditional_operations(self, engine, test_osm, manual_check):
        if not test_osm:
            return
        # 1 perform action
        payload = '{member_vnf_index: "2", primitive: touch, primitive_params: { filename: /home/ubuntu/OSMTESTNBI }}'
        engine.test("DEPLOY{}".format(self.step), "Executer service primitive over NS", "POST",
                    "/nslcm/v1/ns_instances/<{}>/action".format(self.ns_test), headers_yaml, payload,
                    201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
        nslcmop2_action = "DEPLOY{}".format(self.step)
        self.step += 1
        # Wait until status is Ok
        self._wait_nslcmop_ready(engine, nslcmop2_action, timeout_deploy)
        if manual_check:
            input('NS service primitive has been executed. Check that file /home/ubuntu/OSMTESTNBI is present at '
                  'TODO_PUT_IP')
        else:
            cmds = {'1': [''], '2': ['ls -lrt /home/ubuntu/OSMTESTNBI', ]}
            uss = {'1': "ubuntu", '2': "ubuntu"}
            pss = {'1': "osm4u", '2': "osm4u"}
            self.test_ns(engine, test_osm, cmds, uss, pss, self.keys, self.timeout)

        # # 2 perform scale out
        # payload = '{scaleType: SCALE_VNF, scaleVnfData: {scaleVnfType: SCALE_OUT, scaleByStepData: ' \
        #           '{scaling-group-descriptor: scale_dataVM, member-vnf-index: "1"}}}'
        # engine.test("DEPLOY{}".format(self.step), "Execute scale action over NS", "POST",
        #             "/nslcm/v1/ns_instances/<{}>/scale".format(self.ns_test), headers_yaml, payload,
        #             201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
        # nslcmop2_scale_out = "DEPLOY{}".format(self.step)
        # self._wait_nslcmop_ready(engine, nslcmop2_scale_out, timeout_deploy)
        # if manual_check:
        #     input('NS scale out done. Check that file /home/ubuntu/touched is present and new VM is created')
        # # TODO check automatic
        #
        # # 2 perform scale in
        # payload = '{scaleType: SCALE_VNF, scaleVnfData: {scaleVnfType: SCALE_IN, scaleByStepData: ' \
        #           '{scaling-group-descriptor: scale_dataVM, member-vnf-index: "1"}}}'
        # engine.test("DEPLOY{}".format(self.step), "Execute scale action over NS", "POST",
        #             "/nslcm/v1/ns_instances/<{}>/scale".format(self.ns_test), headers_yaml, payload,
        #             201, {"Location": "nslcm/v1/ns_lcm_op_occs/", "Content-Type": "application/yaml"}, "yaml")
        # nslcmop2_scale_in = "DEPLOY{}".format(self.step)
        # self._wait_nslcmop_ready(engine, nslcmop2_scale_in, timeout_deploy)
        # if manual_check:
        #     input('NS scale in done. Check that file /home/ubuntu/touched is updated and new VM is deleted')
        # # TODO check automatic


class TestDescriptors:
    description = "Test VNFD, NSD, PDU descriptors CRUD and dependencies"

    def __init__(self):
        self.step = 0
        self.vnfd_filename = "hackfest_3charmed_vnfd.tar.gz"
        self.nsd_filename = "hackfest_3charmed_nsd.tar.gz"
        self.descriptor_url = "https://osm-download.etsi.org/ftp/osm-3.0-three/2nd-hackfest/packages/"
        self.vnfd_id = None
        self.nsd_id = None

    def run(self, engine, test_osm, manual_check, test_params=None):
        engine.get_autorization()
        temp_dir = os.path.dirname(os.path.abspath(__file__)) + "/temp/"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        # download files
        for filename in (self.vnfd_filename, self.nsd_filename):
            filename_path = temp_dir + filename
            if not os.path.exists(filename_path):
                with open(filename_path, "wb") as file:
                    response = requests.get(self.descriptor_url + filename)
                    if response.status_code >= 300:
                        raise TestException("Error downloading descriptor from '{}': {}".format(
                            self.descriptor_url + filename, response.status_code))
                    file.write(response.content)

        vnfd_filename_path = temp_dir + self.vnfd_filename
        nsd_filename_path = temp_dir + self.nsd_filename

        # vnfd CREATE AND UPLOAD in one step:
        test_name = "DESCRIPTOR{}".format(self.step)
        engine.test(test_name, "Onboard VNFD in one step", "POST",
                    "/vnfpkgm/v1/vnf_packages_content", headers_zip_yaml, "@b" + vnfd_filename_path, 201,
                    {"Location": "/vnfpkgm/v1/vnf_packages_content/", "Content-Type": "application/yaml"}, "yaml")
        self.vnfd_id = engine.test_ids[test_name]
        self.step += 1

        # get vnfd descriptor
        engine.test("DESCRIPTOR" + str(self.step), "Get VNFD descriptor", "GET",
                    "/vnfpkgm/v1/vnf_packages/{}".format(self.vnfd_id), headers_yaml, None, 200, r_header_yaml, "yaml")
        self.step += 1

        # get vnfd file descriptor
        engine.test("DESCRIPTOR" + str(self.step), "Get VNFD file descriptor", "GET",
                    "/vnfpkgm/v1/vnf_packages/{}/vnfd".format(self.vnfd_id), headers_text, None, 200,
                    r_header_text, "text", temp_dir+"vnfd-yaml")
        self.step += 1
        # TODO compare files: diff vnfd-yaml hackfest_3charmed_vnfd/hackfest_3charmed_vnfd.yaml

        # get vnfd zip file package
        engine.test("DESCRIPTOR" + str(self.step), "Get VNFD zip package", "GET",
                    "/vnfpkgm/v1/vnf_packages/{}/package_content".format(self.vnfd_id), headers_zip, None, 200,
                    r_header_zip, "zip", temp_dir+"vnfd-zip")
        self.step += 1
        # TODO compare files: diff vnfd-zip hackfest_3charmed_vnfd.tar.gz

        # get vnfd artifact
        engine.test("DESCRIPTOR" + str(self.step), "Get VNFD artifact package", "GET",
                    "/vnfpkgm/v1/vnf_packages/{}/artifacts/icons/osm.png".format(self.vnfd_id), headers_zip, None, 200,
                    r_header_octect, "octet-string", temp_dir+"vnfd-icon")
        self.step += 1
        # TODO compare files: diff vnfd-icon hackfest_3charmed_vnfd/icons/osm.png

        # nsd CREATE AND UPLOAD in one step:
        test_name = "DESCRIPTOR{}".format(self.step)
        engine.test(test_name, "Onboard NSD in one step", "POST",
                    "/nsd/v1/ns_descriptors_content", headers_zip_yaml, "@b" + nsd_filename_path, 201,
                    {"Location": "/nsd/v1/ns_descriptors_content/", "Content-Type": "application/yaml"}, "yaml")
        self.nsd_id = engine.test_ids[test_name]
        self.step += 1

        # get nsd descriptor
        engine.test("DESCRIPTOR" + str(self.step), "Get NSD descriptor", "GET",
                    "/nsd/v1/ns_descriptors/{}".format(self.nsd_id), headers_yaml, None, 200, r_header_yaml, "yaml")
        self.step += 1

        # get nsd file descriptor
        engine.test("DESCRIPTOR" + str(self.step), "Get NSD file descriptor", "GET",
                    "/nsd/v1/ns_descriptors/{}/nsd".format(self.nsd_id), headers_text, None, 200,
                    r_header_text, "text", temp_dir+"nsd-yaml")
        self.step += 1
        # TODO compare files: diff nsd-yaml hackfest_3charmed_nsd/hackfest_3charmed_nsd.yaml

        # get nsd zip file package
        engine.test("DESCRIPTOR" + str(self.step), "Get NSD zip package", "GET",
                    "/nsd/v1/ns_descriptors/{}/nsd_content".format(self.nsd_id), headers_zip, None, 200,
                    r_header_zip, "zip", temp_dir+"nsd-zip")
        self.step += 1
        # TODO compare files: diff nsd-zip hackfest_3charmed_nsd.tar.gz

        # get nsd artifact
        engine.test("DESCRIPTOR" + str(self.step), "Get NSD artifact package", "GET",
                    "/nsd/v1/ns_descriptors/{}/artifacts/icons/osm.png".format(self.nsd_id), headers_zip, None, 200,
                    r_header_octect, "octet-string", temp_dir+"nsd-icon")
        self.step += 1
        # TODO compare files: diff nsd-icon hackfest_3charmed_nsd/icons/osm.png

        # vnfd DELETE
        test_rest.test("DESCRIPTOR" + str(self.step), "Delete VNFD conflict", "DELETE",
                       "/vnfpkgm/v1/vnf_packages/{}".format(self.vnfd_id), headers_yaml, None, 409, None, None)
        self.step += 1

        test_rest.test("DESCRIPTOR" + str(self.step), "Delete VNFD force", "DELETE",
                       "/vnfpkgm/v1/vnf_packages/{}?FORCE=TRUE".format(self.vnfd_id), headers_yaml, None, 204, None, 0)
        self.step += 1

        # nsd DELETE
        test_rest.test("DESCRIPTOR" + str(self.step), "Delete NSD", "DELETE",
                       "/nsd/v1/ns_descriptors/{}".format(self.nsd_id), headers_yaml, None, 204, None, 0)
        self.step += 1


class TestNstTemplates:
    description = "Upload a NST to OSM"

    def __init__(self):
        self.nst_filenames = ("@./cirros_slice/cirros_slice.yaml")

    def run(self, engine, test_osm, manual_check, test_params=None):
        # nst CREATE
        engine.get_autorization()
        r = engine.test("NST", "Onboard NST", "POST", "/nst/v1/netslice_templates_content", headers_yaml, 
                        self.nst_filenames, 
                        201, {"Location": "/nst/v1/netslice_templates_content", "Content-Type": "application/yaml"}, 
                        "yaml")
        location = r.headers["Location"]
        nst_id = location[location.rfind("/")+1:]

        # nstd SHOW OSM format
        r = engine.test("NST", "Show NSTD OSM format", "GET", 
                        "/nst/v1/netslice_templates_content/{}".format(nst_id), headers_json, None, 
                        200, r_header_json, "json")      

        # nstd DELETE
        r = engine.test("NST", "Delete NSTD", "DELETE", 
                        "/nst/v1/netslice_templates_content/{}".format(nst_id), headers_json, None, 
                        204, None, 0)


if __name__ == "__main__":
    global logger
    test = ""

    # Disable warnings from self-signed certificates.
    requests.packages.urllib3.disable_warnings()
    try:
        logging.basicConfig(format="%(levelname)s %(message)s", level=logging.ERROR)
        logger = logging.getLogger('NBI')
        # load parameters and configuration
        opts, args = getopt.getopt(sys.argv[1:], "hvu:p:",
                                   ["url=", "user=", "password=", "help", "version", "verbose", "no-verbose",
                                    "project=", "insecure", "timeout", "timeout-deploy", "timeout-configure",
                                    "test=", "list", "test-osm", "manual-check", "params="])
        url = "https://localhost:9999/osm"
        user = password = project = "admin"
        test_osm = False
        manual_check = False
        verbose = 0
        verify = True
        test_classes = {
            "NonAuthorized": TestNonAuthorized,
            "FakeVIM": TestFakeVim,
            "TestUsersProjects": TestUsersProjects,
            "VIM-SDN": TestVIMSDN,
            "Deploy-Custom": TestDeploy,
            "Deploy-Hackfest-Cirros": TestDeployHackfestCirros,
            "Deploy-Hackfest-Cirros-Scaling": TestDeployHackfestCirrosScaling,
            "Deploy-Hackfest-3Charmed": TestDeployHackfest3Charmed,
            "Deploy-Hackfest-4": TestDeployHackfest4,
            "Deploy-CirrosMacIp": TestDeployIpMac,
            "TestDescriptors": TestDescriptors,
            "TestDeployHackfest1": TestDeployHackfest1,
            # "Deploy-MultiVIM": TestDeployMultiVIM,
            "Upload-Slice-Template": TestNstTemplates,
        }
        test_to_do = []
        test_params = {}

        for o, a in opts:
            # print("parameter:", o, a)
            if o == "--version":
                print("test version " + __version__ + ' ' + version_date)
                exit()
            elif o == "--list":
                for test, test_class in test_classes.items():
                    print("{:20} {}".format(test + ":", test_class.description))
                exit()
            elif o in ("-v", "--verbose"):
                verbose += 1
            elif o == "no-verbose":
                verbose = -1
            elif o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o == "--test-osm":
                test_osm = True
            elif o == "--manual-check":
                manual_check = True
            elif o == "--url":
                url = a
            elif o in ("-u", "--user"):
                user = a
            elif o in ("-p", "--password"):
                password = a
            elif o == "--project":
                project = a
            elif o == "--test":
                # print("asdfadf", o, a, a.split(","))
                for _test in a.split(","):
                    if _test not in test_classes:
                        print("Invalid test name '{}'. Use option '--list' to show available tests".format(_test),
                              file=sys.stderr)
                        exit(1)
                    test_to_do.append(_test)
            elif o == "--params":
                param_key, _, param_value = a.partition("=")
                text_index = len(test_to_do)
                if text_index not in test_params:
                    test_params[text_index] = {}
                test_params[text_index][param_key] = param_value
            elif o == "--insecure":
                verify = False
            elif o == "--timeout":
                timeout = int(a)
            elif o == "--timeout-deploy":
                timeout_deploy = int(a)
            elif o == "--timeout-configure":
                timeout_configure = int(a)
            else:
                assert False, "Unhandled option"
        if verbose == 0:
            logger.setLevel(logging.WARNING)
        elif verbose > 1:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.ERROR)

        test_rest = TestRest(url, user=user, password=password, project=project)
        # print("tests to do:", test_to_do)
        if test_to_do:
            text_index = 0
            for test in test_to_do:
                text_index += 1
                test_class = test_classes[test]
                test_class().run(test_rest, test_osm, manual_check, test_params.get(text_index))
        else:
            for test, test_class in test_classes.items():
                test_class().run(test_rest, test_osm, manual_check, test_params.get(0))
        exit(0)

        # get token
        print("PASS")

    except TestException as e:
        logger.error(test + "Test {} Exception: {}".format(test, str(e)))
        exit(1)
    except getopt.GetoptError as e:
        logger.error(e)
        print(e, file=sys.stderr)
        exit(1)
    except Exception as e:
        logger.critical(test + " Exception: " + str(e), exc_info=True)
