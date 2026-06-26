package glitch

import data.glitch_lib

bind_name_pattern := "(?i)(.*\\bip\\b.*|.*\\bhost\\b.*|.*bind.*|.*listen.*|.*address.*|.*addr.*|.*interface.*|.*endpoint.*|.*socket.*|.*advertise.*)"

wildcard_ips := {"0.0.0.0", "::", "*"}

wildcard_cidr_values := {"0.0.0.0/0", "::/0", "*", "Any"}

cidr_name_pattern := "(?i).*(cidr|source_range|allowed_ip|source_ip|ingress).*"

is_wildcard_ip(value) {
    value.ir_type == "String"
    value.value == wildcard_ips[_]
}

is_bind_name(name) {
    regex.match(bind_name_pattern, name)
}

is_hash_key_bind(key) {
    key.ir_type == "String"
    is_bind_name(key.value)
}

is_hash_key_bind(key) {
    key.ir_type == "VariableReference"
    is_bind_name(key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_bind_name(node.name)
    is_wildcard_ip(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is configured to listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    is_bind_name(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is configured to listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    entry := hash.value[_]
    is_hash_key_bind(entry.key)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is configured to listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    regex.match(cidr_name_pattern, attr.name)
    attr.value.ir_type == "String"
    attr.value.value == wildcard_cidr_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Unrestricted CIDR range allows connections from any source IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    regex.match(cidr_name_pattern, attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    elem.value == wildcard_cidr_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Unrestricted CIDR range in list allows connections from any source IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "publicly_accessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Resource is publicly accessible without IP restriction. (CWE-1327)"
    }
}