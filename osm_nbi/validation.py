# -*- coding: utf-8 -*-

from jsonschema import validate as js_v, exceptions as js_e

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"
__version__ = "0.1"
version_date = "Mar 2018"

"""
Validator of input data using JSON schemas for those items that not contains an  OSM yang information model
"""

# Basis schemas
patern_name = "^[ -~]+$"
passwd_schema = {"type": "string", "minLength": 1, "maxLength": 60}
nameshort_schema = {"type": "string", "minLength": 1, "maxLength": 60, "pattern": "^[^,;()'\"]+$"}
name_schema = {"type": "string", "minLength": 1, "maxLength": 255, "pattern": "^[^,;()'\"]+$"}
string_schema = {"type": "string", "minLength": 1, "maxLength": 255}
xml_text_schema = {"type": "string", "minLength": 1, "maxLength": 1000, "pattern": "^[^']+$"}
description_schema = {"type": ["string", "null"], "maxLength": 255, "pattern": "^[^'\"]+$"}
id_schema_fake = {"type": "string", "minLength": 2, "maxLength": 36}
bool_schema = {"type": "boolean"}
null_schema = {"type": "null"}
# "pattern": "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"
id_schema = {"type": "string", "pattern": "^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$"}
time_schema = {"type": "string", "pattern": "^[0-9]{4}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]([0-5]:){2}"}
pci_schema = {"type": "string", "pattern": "^[0-9a-fA-F]{4}(:[0-9a-fA-F]{2}){2}\.[0-9a-fA-F]$"}
http_schema = {"type": "string", "pattern": "^https?://[^'\"=]+$"}
bandwidth_schema = {"type": "string", "pattern": "^[0-9]+ *([MG]bps)?$"}
memory_schema = {"type": "string", "pattern": "^[0-9]+ *([MG]i?[Bb])?$"}
integer0_schema = {"type": "integer", "minimum": 0}
integer1_schema = {"type": "integer", "minimum": 1}
path_schema = {"type": "string", "pattern": "^(\.){0,2}(/[^/\"':{}\(\)]+)+$"}
vlan_schema = {"type": "integer", "minimum": 1, "maximum": 4095}
vlan1000_schema = {"type": "integer", "minimum": 1000, "maximum": 4095}
mac_schema = {"type": "string",
              "pattern": "^[0-9a-fA-F][02468aceACE](:[0-9a-fA-F]{2}){5}$"}  # must be unicast: LSB bit of MSB byte ==0
# mac_schema={"type":"string", "pattern":"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"}
ip_schema = {"type": "string",
             "pattern": "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"}
ip_prefix_schema = {"type": "string",
                    "pattern": "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                               "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(30|[12]?[0-9])$"}
port_schema = {"type": "integer", "minimum": 1, "maximum": 65534}
object_schema = {"type": "object"}
schema_version_2 = {"type": "integer", "minimum": 2, "maximum": 2}
# schema_version_string={"type":"string","enum": ["0.1", "2", "0.2", "3", "0.3"]}
log_level_schema = {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]}
checksum_schema = {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"}
size_schema = {"type": "integer", "minimum": 1, "maximum": 100}

ns_instantiate_vdu = {
    "title": "ns action instantiate input schema for vdu",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "id": name_schema,
        "volume": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "name": name_schema,
                    "vim-volume-id": name_schema,
                },
                "required": ["name", "vim-volume-id"],
                "additionalProperties": False
            }
        },
        "interface": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "name": name_schema,
                    "ip-address": ip_schema,
                    "mac-address": mac_schema,
                    "floating-ip-required": bool_schema,
                },
                "required": ["name"],
                "additionalProperties": False
            }
        }
    },
    "required": ["id"],
    "additionalProperties": False
}

ip_profile_dns_schema = {
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "properties": {
            "address": ip_schema,
        },
        "required": ["address"],
        "additionalProperties": False
    }
}

ip_profile_dhcp_schema = {
    "type": "object",
    "properties": {
        "enabled": {"type": "boolean"},
        "count": integer1_schema,
        "start-address": ip_schema
    },
    "additionalProperties": False,
}

ip_profile_schema = {
    "title": "ip profile validation schame",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "ip-version": {"enum": ["ipv4", "ipv6"]},
        "subnet-address": ip_prefix_schema,
        "gateway-address": ip_schema,
        "dns-server": ip_profile_dns_schema,
        "dhcp-params": ip_profile_dhcp_schema,
    }
}

ip_profile_update_schema = {
    "title": "ip profile validation schame",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "ip-version": {"enum": ["ipv4", "ipv6"]},
        "subnet-address": {"oneOf": [null_schema, ip_prefix_schema]},
        "gateway-address": {"oneOf": [null_schema, ip_schema]},
        "dns-server": {"oneOf": [null_schema, ip_profile_dns_schema]},

        "dhcp-params": {"oneOf": [null_schema, ip_profile_dhcp_schema]},
    },
    "additionalProperties": False
}

ns_instantiate_internal_vld = {
    "title": "ns action instantiate input schema for vdu",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "name": name_schema,
        "vim-network-name": name_schema,
        "ip-profile": ip_profile_update_schema,
        "internal-connection-point": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "id-ref": name_schema,
                    "ip-address": ip_schema,
                },
                "required": ["id-ref", "ip-address"],
                "additionalProperties": False
            },
        }
    },
    "required": ["name"],
    "minProperties": 2,
    "additionalProperties": False
}

ns_instantiate = {
    "title": "ns action instantiate input schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "nsName": name_schema,
        "nsDescription": {"oneOf": [description_schema, {"type": "null"}]},
        "nsdId": id_schema,
        "vimAccountId": id_schema,
        "ssh_keys": {"type": "string"},
        "nsr_id": id_schema,
        "vnf": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "member-vnf-index": name_schema,
                    "vimAccountId": id_schema,
                    "vdu": {
                        "type": "array",
                        "minItems": 1,
                        "items": ns_instantiate_vdu,
                    },
                    "internal-vld": {
                        "type": "array",
                        "minItems": 1,
                        "items": ns_instantiate_internal_vld
                    }
                },
                "required": ["member-vnf-index"],
                "minProperties": 2,
                "additionalProperties": False
            }
        },
        "vld": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "name": string_schema,
                    "vim-network-name": {"OneOf": [string_schema, object_schema]},
                    "ip-profile": object_schema,
                },
                "required": ["name"],
                "additionalProperties": False
            }
        },
    },
    "required": ["nsName", "nsdId", "vimAccountId"],
    "additionalProperties": False
}

ns_action = {   # TODO for the moment it is only contemplated the vnfd primitive execution
    "title": "ns action input schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "member_vnf_index": name_schema,
        "vnf_member_index": name_schema,  # TODO for backward compatibility. To remove in future
        "vdu_id": name_schema,
        "primitive": name_schema,
        "primitive_params": {"type": "object"},
    },
    "required": ["primitive", "primitive_params"],   # TODO add member_vnf_index
    "additionalProperties": False
}
ns_scale = {   # TODO for the moment it is only VDU-scaling
    "title": "ns scale input schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "scaleType": {"enum": ["SCALE_VNF"]},
        "scaleVnfData": {
            "type": "object",
            "properties": {
                "vnfInstanceId": name_schema,
                "scaleVnfType": {"enum": ["SCALE_OUT", 'SCALE_IN']},
                "scaleByStepData": {
                    "type": "object",
                    "properties": {
                        "scaling-group-descriptor": name_schema,
                        "member-vnf-index": name_schema,
                        "scaling-policy": name_schema,
                    },
                    "required": ["scaling-group-descriptor", "member-vnf-index"],
                    "additionalProperties": False
                },
            },
            "required": ["scaleVnfType", "scaleByStepData"],  # vnfInstanceId
            "additionalProperties": False
        },
        "scaleTime": time_schema,
    },
    "required": ["scaleType", "scaleVnfData"],
    "additionalProperties": False
}


schema_version = {"type": "string", "enum": ["1.0"]}
vim_account_edit_schema = {
    "title": "vim_account edit input schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "name": name_schema,
        "description": description_schema,
        "type": nameshort_schema,  # currently "openvim" or "openstack", can be enlarged with plugins
        "vim": name_schema,
        "datacenter": name_schema,
        "vim_url": description_schema,
        "vim_url_admin": description_schema,
        "vim_tenant": name_schema,
        "vim_tenant_name": name_schema,
        "vim_username": nameshort_schema,
        "vim_password": nameshort_schema,
        "config": {"type": "object"}
    },
    "additionalProperties": False
}
schema_type = {"type": "string"}

vim_account_new_schema = {
    "title": "vim_account creation input schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "schema_version": schema_version,
        "schema_type": schema_type,
        "name": name_schema,
        "description": description_schema,
        "vim": name_schema,
        "datacenter": name_schema,
        "vim_type": {"enum": ["openstack", "openvim", "vmware", "opennebula", "aws"]},
        "vim_url": description_schema,
        # "vim_url_admin": description_schema,
        # "vim_tenant": name_schema,
        "vim_tenant_name": name_schema,
        "vim_user": nameshort_schema,
        "vim_password": nameshort_schema,
        "config": {"type": "object"}
    },
    "required": ["name", "vim_url", "vim_type", "vim_user", "vim_password", "vim_tenant_name"],
    "additionalProperties": False
}


sdn_properties = {
    "name": name_schema,
    "description": description_schema,
    "dpid": {"type": "string", "pattern": "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){7}$"},
    "ip": ip_schema,
    "port": port_schema,
    "type": {"type": "string", "enum": ["opendaylight", "floodlight", "onos"]},
    "version": {"type": "string", "minLength": 1, "maxLength": 12},
    "user": nameshort_schema,
    "password": passwd_schema
}
sdn_new_schema = {
    "title": "sdn controller information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": sdn_properties,
    "required": ["name", "port", 'ip', 'dpid', 'type'],
    "additionalProperties": False
}
sdn_edit_schema = {
    "title": "sdn controller update information schema",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": sdn_properties,
    # "required": ["name", "port", 'ip', 'dpid', 'type'],
    "additionalProperties": False
}
sdn_port_mapping_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "sdn port mapping information schema",
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "compute_node": nameshort_schema,
            "ports": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "pci": pci_schema,
                        "switch_port": nameshort_schema,
                        "switch_mac": mac_schema
                    },
                    "required": ["pci"]
                }
            }
        },
        "required": ["compute_node", "ports"]
    }
}
sdn_external_port_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "External port ingformation",
    "type": "object",
    "properties": {
        "port": {"type": "string", "minLength": 1, "maxLength": 60},
        "vlan": vlan_schema,
        "mac": mac_schema
    },
    "required": ["port"]
}


nbi_new_input_schemas = {
    "vim_accounts": vim_account_new_schema,
    "sdns": sdn_new_schema,
    "ns_instantiate": ns_instantiate,
    "ns_action": ns_action,
    "ns_scale": ns_scale
}

nbi_edit_input_schemas = {
    "vim_accounts": vim_account_edit_schema,
    "sdns": sdn_edit_schema
}


class ValidationError(Exception):
    pass


def validate_input(indata, item, new=True):
    """
    Validates input data agains json schema
    :param indata: user input data. Should be a dictionary
    :param item: can be users, projects, vims, sdns, ns_xxxxx
    :param new: True if the validation is for creating or False if it is for editing
    :return: None if ok, raises ValidationError exception otherwise
    """
    try:
        if new:
            schema_to_use = nbi_new_input_schemas.get(item)
        else:
            schema_to_use = nbi_edit_input_schemas.get(item)
        if schema_to_use:
            js_v(indata, schema_to_use)
        return None
    except js_e.ValidationError as e:
        if e.path:
            error_pos = "at '" + ":".join(map(str, e.path)) + "'"
        else:
            error_pos = ""
        raise ValidationError("Format error {} '{}' ".format(error_pos, e.message))
