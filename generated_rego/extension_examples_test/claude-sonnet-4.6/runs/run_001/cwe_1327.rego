package glitch

import data.glitch_lib

unrestricted_ip_values := {"0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0"}
unrestricted_cidr_values := {"0.0.0.0/0", "::/0"}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    lower(value.value) == unrestricted_ip_values[_]
}

is_unrestricted_ip(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    lower(item.value) == unrestricted_ip_values[_]
}

is_unrestricted_cidr(value) {
    value.ir_type == "String"
    lower(value.value) == unrestricted_cidr_values[_]
}

is_unrestricted_cidr(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    lower(item.value) == unrestricted_cidr_values[_]
}

is_binding_name(name) {
    regex.match("(?i).*(bind|listen).*", name)
}

is_binding_name(name) {
    regex.match(`(?i)(^|[^a-zA-Z])(ip|addr|address|hostname|host|interface|endpoint)([^a-zA-Z]|$)`, name)
}

is_cidr_name(name) {
    regex.match("(?i).*(cidr|source_range|allowed_ip|accessible_from|source_cidr).*", name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_binding_name(v.name)
    is_unrestricted_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_name(attr.name)
    is_unrestricted_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_binding_name(entry.key.value)
    is_unrestricted_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "VariableReference"
    is_binding_name(entry.key.value)
    is_unrestricted_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_cidr_name(v.name)
    is_unrestricted_cidr(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Unrestricted CIDR block - Network rules should not allow all traffic from 0.0.0.0/0 or ::/0. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_cidr_name(attr.name)
    is_unrestricted_cidr(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted CIDR block - Network rules should not allow all traffic from 0.0.0.0/0 or ::/0. (CWE-1327)"
    }
}