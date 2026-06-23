package glitch

import data.glitch_lib

wildcard_ip_regex := "(?i)(0\\.0\\.0\\.0(/0)?|::|::/0|\\*|any)(:[0-9]*)?"
port_binding_regex := "(0\\.0\\.0\\.0|\\*):[0-9]+|^:[0-9]+"
wildcard_cidr_regex := "(?i)^(0\\.0\\.0\\.0/0|::/0|\\*|any|internet|all)$"

is_wildcard_ip(value) {
    value.ir_type == "String"
    regex.match(wildcard_ip_regex, value.value)
}

is_wildcard_ip(value) {
    value.ir_type == "String"
    regex.match(port_binding_regex, value.value)
}

is_wildcard_cidr(value) {
    value.ir_type == "String"
    regex.match(wildcard_cidr_regex, value.value)
}

is_wildcard_cidr(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    regex.match(wildcard_cidr_regex, elem.value)
}

is_public_flag(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_public_flag(value) {
    value.ir_type == "String"
    regex.match("(?i)^(enabled|yes|allow)$", value.value)
}

is_binding_field(name) {
    regex.match("(?i)(^:?ip$|listen|bind|addr|ip_address|net_bind|interface|socket|api_listen|metrics_listen|endpoint|rpc_addr|advertise_addr|client_addr|grpc_address|http_addr)", name)
}

is_cidr_field(name) {
    regex.match("(?i)(cidr|source_range|ingress|inbound|allowed_ip|ip_range|source_address|allowed_source|accessible_cidr)", name)
}

is_public_access_field(name) {
    regex.match("(?i)(publicly_accessible|public_access|public_ip_enabled|assign_public_ip|public_network_access|enable_public|internet_accessible|open_to_internet|external_access)", name)
}

hash_key_name(key) = name {
    key.ir_type == "String"
    name := key.value
}

hash_key_name(key) = name {
    key.ir_type == "VariableReference"
    name := key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_field(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent wildcard addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_binding_field(v.name)
    is_wildcard_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent wildcard addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    name := hash_key_name(entry.key)
    is_binding_field(name)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent wildcard addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_cidr_field(attr.name)
    is_wildcard_cidr(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network ingress rules should not allow traffic from all sources (0.0.0.0/0). (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_public_access_field(attr.name)
    is_public_flag(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Public accessibility flags expose resources to all networks. (CWE-1327)"
    }
}