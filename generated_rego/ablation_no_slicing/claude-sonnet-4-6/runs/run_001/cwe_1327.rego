package glitch

import data.glitch_lib

binding_name_re := "(?i)(listen[_.]?(addr(ess)?|on|ip)|(^|[^a-zA-Z])bind([^a-zA-Z]|$)|bindip|net[_.]?bind|ip[_.]?addr(ess)?|network_interface|server_address|connect_address|endpoint|(^|[_\\[]:?)addr(\\]|_|$)|^ip$|^host$)"

cidr_name_re := "(?i)(cidr|source_range|ip_range|from_ip|access_cidr|ingress_cidr|allowed_cidr)"

public_name_re := "(?i)(publicly_accessible|public_access|public_ip_enabled|internet_facing|assign_public_ip|public_network_access|external_access)"

wildcard_ip_re := "^(0\\.0\\.0\\.0|:::|::)$"

unrestricted_cidr_re := "(0\\.0\\.0\\.0/0|::/0)"

is_wildcard_ip(v) {
    v.ir_type == "String"
    regex.match(wildcard_ip_re, v.value)
}

is_unrestricted_cidr_val(v) {
    v.ir_type == "String"
    regex.match(unrestricted_cidr_re, v.value)
}

is_unrestricted_cidr_val(v) {
    v.ir_type == "Array"
    elem := v.value[_]
    elem.ir_type == "String"
    regex.match(unrestricted_cidr_re, elem.value)
}

is_public_true(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_public_true(v) {
    v.ir_type == "String"
    regex.match("(?i)^(true|yes|enabled)$", v.value)
}

key_name(key) = name {
    key.ir_type == "String"
    name := key.value
}

key_name(key) = name {
    key.ir_type == "VariableReference"
    name := trim_prefix(key.value, ":")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(binding_name_re, v.name)
    is_wildcard_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(binding_name_re, attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    kname := key_name(entry.key)
    regex.match(binding_name_re, kname)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address in hash configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(cidr_name_re, v.name)
    is_unrestricted_cidr_val(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Overly permissive CIDR range - Network access is unrestricted via wildcard CIDR block. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(cidr_name_re, attr.name)
    is_unrestricted_cidr_val(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive CIDR range - Network access is unrestricted via wildcard CIDR block. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(public_name_re, v.name)
    is_public_true(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Public network accessibility enabled - Resource is explicitly configured to be publicly accessible. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(public_name_re, attr.name)
    is_public_true(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public network accessibility enabled - Resource is explicitly configured to be publicly accessible. (CWE-1327)"
    }
}