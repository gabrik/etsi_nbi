#! /usr/bin/python3
# -*- coding: utf-8 -*-

import getopt
import sys
import requests
#import base64
#from os.path import getsize, basename
#from hashlib import md5
import json
import logging
import yaml
#import json
import tarfile
from os import makedirs
from copy import deepcopy

__author__ = "Alfonso Tierno, alfonso.tiernosepulveda@telefonica.com"
__date__ = "$2018-03-01$"
__version__ = "0.1"
version_date = "Mar 2018"


def usage():
    print("Usage: ", sys.argv[0], "[options]")
    print("      --version: prints current version")
    print("      -f|--file FILE: file to be sent")
    print("      -h|--help: shows this help")
    print("      -u|--url URL: complete server URL")
    print("      -s|--chunk-size SIZE: size of chunks, by default 1000")
    print("      -t|--token TOKEN: Authorizaton token, previously obtained from server")
    print("      -v|--verbose print debug information, can be used several times")
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
# test without authorization
test_not_authorized_list = (
    ("Invalid token", "GET", "/admin/v1/users", headers_json, None, 401, r_header_json, "json"),
    ("Invalid URL", "POST", "/admin/v1/nonexist", headers_yaml, None, 405, r_header_yaml, "yaml"),
    ("Invalid version", "DELETE", "/admin/v2/users", headers_yaml, None, 405, r_header_yaml, "yaml"),
)

# test ones authorized
test_authorized_list = (
    ("Invalid vnfd id", "GET", "/vnfpkgm/v1/vnf_packages/non-existing-id", headers_json, None, 404, r_header_json, "json"),
    ("Invalid nsd id", "GET", "/nsd/v1/ns_descriptors/non-existing-id", headers_yaml, None, 404, r_header_yaml, "yaml"),
    ("Invalid nsd id", "DELETE", "/nsd/v1/ns_descriptors_content/non-existing-id", headers_yaml, None, 404, r_header_yaml, "yaml"),
)

class TestException(Exception):
    pass


class TestRest:
    def __init__(self, url_base, header_base={}, verify=False):
        self.url_base = url_base
        self.header_base = header_base
        self.s = requests.session()
        self.s.headers = header_base
        self.verify = verify

    def set_header(self, header):
        self.s.headers.update(header)

    def test(self, name, method, url, headers, payload, expected_codes, expected_headers, expected_payload):
        """
        Performs an http request and check http code response. Exit if different than allowed
        :param name:  name of the test
        :param method: HTTP method: GET,PUT,POST,DELETE,...
        :param url: complete URL or relative URL
        :param headers: request headers to add to the base headers
        :param payload: Can be a dict, transformed to json, a text or a file if starts with '@'
        :param expected_codes: expected response codes, can be int, int tuple or int range
        :param expected_headers: expected response headers, dict with key values
        :param expected_payload: expected payload, 0 if empty, 'yaml', 'json', 'text', 'zip'
        :return:
        """
        try:
            if not self.s:
                self.s = requests.session()
            if not url:
                url = self.url_base
            elif not url.startswith("http"):
                url = self.url_base + url
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
    
            test = "Test {} {} {}".format(name, method, url)
            logger.warning(test)
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
                    #r.text
            return r
        except TestException as e:
            logger.error("{} \nRX code{}: {}".format(e, r.status_code, r.text))
            exit(1)
        except IOError as e:
            logger.error("Cannot open file {}".format(e))
            exit(1)


if __name__ == "__main__":
    global logger
    test = ""
    try:
        logging.basicConfig(format="%(levelname)s %(message)s", level=logging.ERROR)
        logger = logging.getLogger('NBI')
        # load parameters and configuration
        opts, args = getopt.getopt(sys.argv[1:], "hvu:p:",
                                   ["url=", "user=", "password=", "help", "version", "verbose", "project=", "insecure"])
        url = "https://localhost:9999/osm"
        user = password = project = "admin"
        verbose = 0
        verify = True

        for o, a in opts:
            if o == "--version":
                print ("test version " + __version__ + ' ' + version_date)
                sys.exit()
            elif o in ("-v", "--verbose"):
                verbose += 1
            elif o in ("no-verbose"):
                verbose = -1
            elif o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("--url"):
                url = a
            elif o in ("-u", "--user"):
                user = a
            elif o in ("-p", "--password"):
                password = a
            elif o in ("--project"):
                project = a
            elif o in ("--insecure"):
                verify = False
            else:
                assert False, "Unhandled option"
        if verbose == 0:
            logger.setLevel(logging.WARNING)
        elif verbose > 1:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.ERROR)

        test_rest = TestRest(url)

        # tests without authorization
        for t in test_not_authorized_list:
            test_rest.test(*t)

        # get token
        r = test_rest.test("Obtain token", "POST", "/admin/v1/tokens", headers_json,
                           {"username": user, "password": password, "project_id": project},
                           (200, 201), {"Content-Type": "application/json"}, "json")
        response = r.json()
        token = response["id"]
        test_rest.set_header({"Authorization": "Bearer {}".format(token)})

        # tests once authorized
        for t in test_authorized_list:
            test_rest.test(*t)

        # nsd CREATE
        r = test_rest.test("Onboard NSD step 1", "POST", "/nsd/v1/ns_descriptors", headers_json, None,
                           201, {"Location": "/nsd/v1/ns_descriptors/", "Content-Type": "application/json"}, "json")
        location = r.headers["Location"]
        nsd_id = location[location.rfind("/")+1:]
        # print(location, nsd_id)

        # nsd UPLOAD test
        r = test_rest.test("Onboard NSD step 2 as TEXT", "PUT", "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
                           r_header_text, "@./cirros_ns/cirros_nsd.yaml", 204, None, 0)

        # nsd SHOW OSM format
        r = test_rest.test("Show NSD OSM format", "GET", "/nsd/v1/ns_descriptors_content/{}".format(nsd_id),
                           headers_json, None, 200, r_header_json, "json")

        # nsd SHOW text
        r = test_rest.test("Show NSD SOL005 text", "GET", "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
                           headers_text, None, 200, r_header_text, "text")

        # nsd UPLOAD ZIP
        makedirs("temp", exist_ok=True)
        tar = tarfile.open("temp/cirros_ns.tar.gz", "w:gz")
        tar.add("cirros_ns")
        tar.close()
        r = test_rest.test("Onboard NSD step 3 replace with ZIP", "PUT", "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
                           r_header_zip, "@b./temp/cirros_ns.tar.gz", 204, None, 0)

        # nsd SHOW OSM format
        r = test_rest.test("Show NSD OSM format", "GET", "/nsd/v1/ns_descriptors_content/{}".format(nsd_id),
                           headers_json, None, 200, r_header_json, "json")

        # nsd SHOW zip
        r = test_rest.test("Show NSD SOL005 zip", "GET", "/nsd/v1/ns_descriptors/{}/nsd_content".format(nsd_id),
                           headers_zip, None, 200, r_header_zip, "zip")

        # nsd SHOW descriptor
        r = test_rest.test("Show NSD descriptor", "GET", "/nsd/v1/ns_descriptors/{}/nsd".format(nsd_id),
                           headers_text, None, 200, r_header_text, "text")
        # nsd SHOW actifact
        r = test_rest.test("Show NSD artifact", "GET", "/nsd/v1/ns_descriptors/{}/artifacts/icons/osm_2x.png".format(nsd_id),
                           headers_text, None, 200, r_header_octect, "text")

        # nsd DELETE
        r = test_rest.test("Delete NSD SOL005 text", "DELETE", "/nsd/v1/ns_descriptors/{}".format(nsd_id),
                           headers_yaml, None, 204, None, 0)

        # vnfd CREATE
        r = test_rest.test("Onboard VNFD step 1", "POST", "/vnfpkgm/v1/vnf_packages", headers_json, None,
                           201, {"Location": "/vnfpkgm/v1/vnf_packages/", "Content-Type": "application/json"}, "json")
        location = r.headers["Location"]
        vnfd_id = location[location.rfind("/")+1:]
        # print(location, vnfd_id)

        # vnfd UPLOAD test
        r = test_rest.test("Onboard VNFD step 2 as TEXT", "PUT", "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
                           r_header_text, "@./cirros_vnf/cirros_vnfd.yaml", 204, None, 0)

        # vnfd SHOW OSM format
        r = test_rest.test("Show VNFD OSM format", "GET", "/vnfpkgm/v1/vnf_packages_content/{}".format(vnfd_id),
                           headers_json, None, 200, r_header_json, "json")

        # vnfd SHOW text
        r = test_rest.test("Show VNFD SOL005 text", "GET", "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
                           headers_text, None, 200, r_header_text, "text")

        # vnfd UPLOAD ZIP
        makedirs("temp", exist_ok=True)
        tar = tarfile.open("temp/cirros_vnf.tar.gz", "w:gz")
        tar.add("cirros_vnf")
        tar.close()
        r = test_rest.test("Onboard VNFD step 3 replace with ZIP", "PUT", "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
                           r_header_zip, "@b./temp/cirros_vnf.tar.gz", 204, None, 0)

        # vnfd SHOW OSM format
        r = test_rest.test("Show VNFD OSM format", "GET", "/vnfpkgm/v1/vnf_packages_content/{}".format(vnfd_id),
                           headers_json, None, 200, r_header_json, "json")

        # vnfd SHOW zip
        r = test_rest.test("Show VNFD SOL005 zip", "GET", "/vnfpkgm/v1/vnf_packages/{}/package_content".format(vnfd_id),
                           headers_zip, None, 200, r_header_zip, "zip")
        # vnfd SHOW descriptor
        r = test_rest.test("Show VNFD descriptor", "GET", "/vnfpkgm/v1/vnf_packages/{}/vnfd".format(vnfd_id),
                           headers_text, None, 200, r_header_text, "text")
        # vnfd SHOW actifact
        r = test_rest.test("Show VNFD artifact", "GET", "/vnfpkgm/v1/vnf_packages/{}/artifacts/icons/cirros-64.png".format(vnfd_id),
                           headers_text, None, 200, r_header_octect, "text")

        # vnfd DELETE
        r = test_rest.test("Delete VNFD SOL005 text", "DELETE", "/vnfpkgm/v1/vnf_packages/{}".format(vnfd_id),
                           headers_yaml, None, 204, None, 0)

        print("PASS")

    except Exception as e:
        if test:
            logger.error(test + " Exception: " + str(e))
            exit(1)
        else:
            logger.critical(test + " Exception: " + str(e), exc_info=True)
