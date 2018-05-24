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
__version__ = "0.2"
version_date = "Jul 2018"


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

    def test(self, name, description, method, url, headers, payload, expected_codes, expected_headers,
             expected_payload):
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
        :param expected_payload: expected payload, 0 if empty, 'yaml', 'json', 'text', 'zip'
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
            # if expected_payload == "zip":
            #     stream = True
            r = getattr(self.s, method.lower())(url, data=payload, headers=headers, verify=self.verify, stream=stream)
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
                elif expected_payload == "zip":
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
                      (200, 201), {"Content-Type": "application/json"}, "json")
        response = r.json()
        self.token = response["id"]
        self.set_header({"Authorization": "Bearer {}".format(self.token)})

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
    def run(engine, test_osm, manual_check):
        test_not_authorized_list = (
            ("NA1", "Invalid token", "GET", "/admin/v1/users", headers_json, None, 401, r_header_json, "json"),
            ("NA2", "Invalid URL", "POST", "/admin/v1/nonexist", headers_yaml, None, 405, r_header_yaml, "yaml"),
            ("NA3", "Invalid version", "DELETE", "/admin/v2/users", headers_yaml, None, 405, r_header_yaml, "yaml"),
        )
        for t in test_not_authorized_list:
            engine.test(*t)


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

    def run(self, engine, test_osm, manual_check):

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

    def run(self, engine, test_osm, manual_check):
        engine.get_autorization()
        # Added SDN
        engine.test("SDN1", "Create SDN", "POST", "/admin/v1/sdns", headers_json, self.sdn, (201, 204),
                    {"Location": "/admin/v1/sdns/", "Content-Type": "application/json"}, "json")
        sleep(5)
        # Edit SDN
        engine.test("SDN1", "Edit SDN", "PATCH", "/admin/v1/sdns/<SDN1>", headers_json, {"name": "new_sdn_name"},
                    (200, 201, 204), r_header_json, "json")
        sleep(5)
        # VIM with SDN
        self.vim["config"]["sdn-controller"] = engine.test_ids["SDN1"]
        self.vim["config"]["sdn-port-mapping"] = self.port_mapping
        engine.test("VIM2", "Create VIM", "POST", "/admin/v1/vim_accounts", headers_json, self.vim, (200, 204, 201),
                    {"Location": "/admin/v1/vim_accounts/", "Content-Type": "application/json"}, "json"),

        self.port_mapping[0]["compute_node"] = "compute node XX"
        engine.test("VIMSDN2", "Edit VIM change port-mapping", "PUT", "/admin/v1/vim_accounts/<VIM2>", headers_json,
                    {"config": {"sdn-port-mapping": self.port_mapping}},
                    (200, 201, 204), {"Content-Type": "application/json"}, "json")
        engine.test("VIMSDN3", "Edit VIM remove port-mapping", "PUT", "/admin/v1/vim_accounts/<VIM2>", headers_json,
                    {"config": {"sdn-port-mapping": None}},
                    (200, 201, 204), {"Content-Type": "application/json"}, "json")
        engine.test("VIMSDN4", "Delete VIM remove port-mapping", "DELETE", "/admin/v1/vim_accounts/<VIM2>",
                    headers_json, None, (202, 201, 204), None, 0)
        engine.test("VIMSDN5", "Delete SDN", "DELETE", "/admin/v1/sdns/<SDN1>", headers_json, None,
                    (202, 201, 204), None, 0)


class TestDeploy:
    description = "Base class for downloading descriptors from ETSI, onboard and deploy in real VIM"

    def __init__(self):
        self.step = 0
        self.nsd_id = None
        self.vim_id = None
        self.nsd_test = None
        self.ns_test = None
        self.vnfds_test = []
        self.descriptor_url = "https://osm-download.etsi.org/ftp/osm-3.0-three/2nd-hackfest/packages/"
        self.vnfd_filenames = ("cirros_vnf.tar.gz",)
        self.nsd_filename = "cirros_2vnf_ns.tar.gz"
        self.uses_configuration = False

    def create_descriptors(self, engine):
        temp_dir = os.path.dirname(__file__) + "/temp/"
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
                engine.test("DEPLOY{}".format(self.step), "Onboard VNFD in one step", "POST",
                            "/vnfpkgm/v1/vnf_packages_content", headers, "@b" + vnfd_filename_path, 201,
                            {"Location": "/vnfpkgm/v1/vnf_packages_content/", "Content-Type": "application/yaml"}, yaml)
                self.vnfds_test.append("DEPLOY" + str(self.step))
                self.step += 1
            else:
                # vnfd CREATE AND UPLOAD ZIP
                engine.test("DEPLOY{}".format(self.step), "Onboard VNFD step 1", "POST", "/vnfpkgm/v1/vnf_packages",
                            headers_json, None, 201,
                            {"Location": "/vnfpkgm/v1/vnf_packages/", "Content-Type": "application/json"}, "json")
                self.vnfds_test.append("DEPLOY" + str(self.step))
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

    def _wait_nslcmop_ready(self, engine, nslcmop_test, timeout_deploy):
        wait = timeout
        while wait >= 0:
            r = engine.test("DEPLOY{}".format(self.step), "Wait to ns lcm operation complete", "GET",
                            "/nslcm/v1/ns_lcm_op_occs/<{}>".format(nslcmop_test), headers_json, None,
                            200, r_header_json, "json")
            nslcmop = r.json()
            if "COMPLETED" in nslcmop["operationState"]:
                break
            elif "FAILED" in nslcmop["operationState"]:
                raise TestException("NS terminate has failed: {}".format(nslcmop["detailed-status"]))
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

    def test_ns(self, engine, test_osm):
        pass

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
            self.test_ns(engine, test_osm)
        self.aditional_operations(engine, test_osm, manual_check)
        self.terminate(engine)
        self.delete_descriptors(engine)


class TestDeployHackfestCirros(TestDeploy):
    description = "Load and deploy Hackfest cirros_2vnf_ns example"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("cirros_vnf.tar.gz",)
        self.nsd_filename = "cirros_2vnf_ns.tar.gz"

    def run(self, engine, test_osm, manual_check, test_params=None):
        super().run(engine, test_osm, manual_check, test_params)


class TestDeployIpMac(TestDeploy):
    description = "Load and deploy descriptor examples setting mac, ip address at descriptor and instantiate params"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("vnfd_2vdu_set_ip_mac2.yaml", "vnfd_2vdu_set_ip_mac.yaml")
        self.nsd_filename = "scenario_2vdu_set_ip_mac.yaml"
        self.descriptor_url = \
            "https://osm.etsi.org/gitweb/?p=osm/RO.git;a=blob_plain;f=test/RO_tests/v3_2vdu_set_ip_mac/"

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
                                {
                                    "name": "iface11",
                                    "floating-ip-required": True,
                                },
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
                                    "ip-address": "10.31.31.21",
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
                    "/vnfpkgm/v1/vnf_packages/<{}>".format(self.vnfds_test[0]),
                    headers_yaml, payload, 200,
                    r_header_yaml, yaml)
        self.vnfds_test.append("DEPLOY" + str(self.step))
        self.step += 1

    def run(self, engine, test_osm, manual_check, test_params=None):
        super().run(engine, test_osm, manual_check, test_params)


class TestDeployHackfest3Charmed(TestDeploy):
    description = "Load and deploy Hackfest 3charmed_ns example. Modifies it for adding scaling and performs " \
                  "primitive actions and scaling"

    def __init__(self):
        super().__init__()
        self.vnfd_filenames = ("hackfest_3charmed_vnfd.tar.gz",)
        self.nsd_filename = "hackfest_3charmed_nsd.tar.gz"
        self.uses_configuration = True

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
        # TODO check automatic

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

    def run(self, engine, test_osm, manual_check, test_params=None):
        super().run(engine, test_osm, manual_check, test_params)


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
            "VIM-SDN": TestVIMSDN,
            "Deploy-Custom": TestDeploy,
            "Deploy-Hackfest-Cirros": TestDeployHackfestCirros,
            "Deploy-Hackfest-3Charmed": TestDeployHackfest3Charmed,
            "Deploy-Hackfest-4": TestDeployHackfest4,
            "Deploy-CirrosMacIp": TestDeployIpMac,
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

        # # tests once authorized
        # for t in test_authorized_list:
        #     test_rest.test(*t)
        #
        # # tests admin
        # for t in test_admin_list1:
        #     test_rest.test(*t)
        #
        # # vnfd CREATE
        # r = test_rest.test("VNFD1", "Onboard VNFD step 1", "POST", "/vnfpkgm/v1/vnf_packages", headers_json, None,
        #                    201, {"Location": "/vnfpkgm/v1/vnf_packages/", "Content-Type": "application/json"}, "json")
        # location = r.headers["Location"]
        # vnfd_id = location[location.rfind("/")+1:]
        # # print(location, vnfd_id)
        #
        # # vnfd UPLOAD test
        # r = test_rest.test("VNFD2", "Onboard VNFD step 2 as TEXT", "PUT",
        #                    "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
        #                    r_header_text, "@./cirros_vnf/cirros_vnfd.yaml", 204, None, 0)
        #
        # # vnfd SHOW OSM format
        # r = test_rest.test("VNFD3", "Show VNFD OSM format", "GET",
        #                    "/vnfpkgm/v1/vnf_packages_content/{}".format(vnfd_id),
        #                    headers_json, None, 200, r_header_json, "json")
        #
        # # vnfd SHOW text
        # r = test_rest.test("VNFD4", "Show VNFD SOL005 text", "GET",
        #                    "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
        #                    headers_text, None, 200, r_header_text, "text")
        #
        # # vnfd UPLOAD ZIP
        # makedirs("temp", exist_ok=True)
        # tar = tarfile.open("temp/cirros_vnf.tar.gz", "w:gz")
        # tar.add("cirros_vnf")
        # tar.close()
        # r = test_rest.test("VNFD5", "Onboard VNFD step 3 replace with ZIP", "PUT",
        #                    "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
        #                    r_header_zip, "@b./temp/cirros_vnf.tar.gz", 204, None, 0)
        #
        # # vnfd SHOW OSM format
        # r = test_rest.test("VNFD6", "Show VNFD OSM format", "GET",
        #                    "/vnfpkgm/v1/vnf_packages_content/{}".format(vnfd_id),
        #                    headers_json, None, 200, r_header_json, "json")
        #
        # # vnfd SHOW zip
        # r = test_rest.test("VNFD7", "Show VNFD SOL005 zip", "GET",
        #                    "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
        #                    headers_zip, None, 200, r_header_zip, "zip")
        # # vnfd SHOW descriptor
        # r = test_rest.test("VNFD8", "Show VNFD descriptor", "GET",
        #                    "/vnfpkgm/v1/vnf_packages/{}/vnfd".format(vnfd_id),
        #                    headers_text, None, 200, r_header_text, "text")
        # # vnfd SHOW actifact
        # r = test_rest.test("VNFD9", "Show VNFD artifact", "GET",
        #                    "/vnfpkgm/v1/vnf_packages/{}/artifacts/icons/cirros-64.png".format(vnfd_id),
        #                    headers_text, None, 200, r_header_octect, "text")
        #
        # # # vnfd DELETE
        # # r = test_rest.test("VNFD10", "Delete VNFD SOL005 text", "DELETE",
        # # "/vnfpkgm/v1/vnf_packages/{}".format(vnfd_id),
        # #                    headers_yaml, None, 204, None, 0)
        #
        # # nsd CREATE
        # r = test_rest.test("NSD1", "Onboard NSD step 1", "POST", "/nsd/v1/ns_descriptors", headers_json, None,
        #                    201, {"Location": "/nsd/v1/ns_descriptors/", "Content-Type": "application/json"}, "json")
        # location = r.headers["Location"]
        # nsd_id = location[location.rfind("/")+1:]
        # # print(location, nsd_id)
        #
        # # nsd UPLOAD test
        # r = test_rest.test("NSD2", "Onboard NSD with missing vnfd", "PUT",
        #                    "/nsd/v1/ns_descriptors/<>/nsd_content?constituent-vnfd.0.vnfd-id-ref"
        #                    "=NONEXISTING-VNFD".format(nsd_id),
        #                    r_header_text, "@./cirros_ns/cirros_nsd.yaml", 409, r_header_yaml, "yaml")
        #
        # # # VNF_CREATE
        # # r = test_rest.test("VNFD5", "Onboard VNFD step 3 replace with ZIP", "PUT",
        # # "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
        # #                    r_header_zip, "@b./temp/cirros_vnf.tar.gz", 204, None, 0)
        #
        # r = test_rest.test("NSD2", "Onboard NSD step 2 as TEXT", "PUT",
        #                    "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
        #                    r_header_text, "@./cirros_ns/cirros_nsd.yaml", 204, None, 0)
        #
        # # nsd SHOW OSM format
        # r = test_rest.test("NSD3", "Show NSD OSM format", "GET", "/nsd/v1/ns_descriptors_content/{}".format(nsd_id),
        #                    headers_json, None, 200, r_header_json, "json")
        #
        # # nsd SHOW text
        # r = test_rest.test("NSD4", "Show NSD SOL005 text", "GET",
        #                    "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
        #                    headers_text, None, 200, r_header_text, "text")
        #
        # # nsd UPLOAD ZIP
        # makedirs("temp", exist_ok=True)
        # tar = tarfile.open("temp/cirros_ns.tar.gz", "w:gz")
        # tar.add("cirros_ns")
        # tar.close()
        # r = test_rest.test("NSD5", "Onboard NSD step 3 replace with ZIP", "PUT",
        #                    "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
        #                    r_header_zip, "@b./temp/cirros_ns.tar.gz", 204, None, 0)
        #
        # # nsd SHOW OSM format
        # r = test_rest.test("NSD6", "Show NSD OSM format", "GET", "/nsd/v1/ns_descriptors_content/{}".format(nsd_id),
        #                    headers_json, None, 200, r_header_json, "json")
        #
        # # nsd SHOW zip
        # r = test_rest.test("NSD7","Show NSD SOL005 zip","GET", "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
        #                    headers_zip, None, 200, r_header_zip, "zip")
        #
        # # nsd SHOW descriptor
        # r = test_rest.test("NSD8", "Show NSD descriptor", "GET", "/nsd/v1/ns_descriptors/{}/nsd".format(nsd_id),
        #                    headers_text, None, 200, r_header_text, "text")
        # # nsd SHOW actifact
        # r = test_rest.test("NSD9", "Show NSD artifact", "GET",
        #                    "/nsd/v1/ns_descriptors/{}/artifacts/icons/osm_2x.png".format(nsd_id),
        #                    headers_text, None, 200, r_header_octect, "text")
        #
        # # vnfd DELETE
        # r = test_rest.test("VNFD10", "Delete VNFD conflict", "DELETE", "/vnfpkgm/v1/vnf_packages/{}".format(vnfd_id),
        #                    headers_yaml, None, 409, r_header_yaml, "yaml")
        #
        # # nsd DELETE
        # r = test_rest.test("NSD10", "Delete NSD SOL005 text", "DELETE", "/nsd/v1/ns_descriptors/{}".format(nsd_id),
        #                    headers_yaml, None, 204, None, 0)
        #
        # # vnfd DELETE
        # r = test_rest.test("VNFD10","Delete VNFD SOL005 text","DELETE", "/vnfpkgm/v1/vnf_packages/{}".format(vnfd_id),
        #                    headers_yaml, None, 204, None, 0)
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
