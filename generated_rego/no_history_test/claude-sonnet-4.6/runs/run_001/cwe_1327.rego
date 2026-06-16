package glitch

import data.glitch_lib

wildcard_bind_values := {"0.0.0.0", "::", "*", "any"}
wildcard_cidr_values := {"0.0.0.0/0", "::/0", "*", "any"}

normalize_name(name) = stripped {
    startswith(name, ":")
    stripped := substring(name, 1, -1)
}

normalize_name(name) = name {
    not startswith(name, ":")
}

is_binding_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)(^|[^a-zA-Z])bind`, name)
}

is_binding_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)(^|[^a-zA-Z])listen`, name)
}

is_binding_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)(^|[^a-zA-Z])addr(ess)?([^a-zA-Z]|$)`, name)
}

is_binding_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)^(host|hostname|server[-_]host|ip[-_]addr(ess)?|socket[-_]?addr(ess)?|endpoint|ip)$`, name)
}

is_cidr_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)^(cidr_blocks?|ipv[46]_cidr_blocks?|source_ranges?|allowed_ranges?|ip_ranges?|source_address|source_cidr|from_cidr|to_cidr|inbound_cidr|ingress_cidr|peer_cidr|remote_ip_prefix)$`, name)
}

is_cidr_name(raw_name) {
    name := normalize_name(raw_name)
    regex.match(`(?i)(^|[^a-zA-Z])cidr([^a-zA-Z]|$)`, name)
}

is_wildcard_bind(value) {
    value.ir_type == "String"
    wildcard_bind_values[value.value]
}

is_wildcard_cidr(value) {
    value.ir_type == "String"
    wildcard_cidr_values[value.value]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_name(attr.name)
    is_wildcard_bind(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Attribute bound to wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_binding_name(v.name)
    is_wildcard_bind(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Variable bound to wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    is_binding_name(entry.key.value)
    is_wildcard_bind(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Hash entry bound to wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    is_binding_name(entry.key.value)
    is_wildcard_bind(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Hash entry bound to wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_cidr_name(attr.name)
    is_wildcard_cidr(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network access permits all sources. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_cidr_name(attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    is_wildcard_cidr(elem)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Array contains wildcard CIDR. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(`(?i)^(publicly_accessible|enable_public_access|public_access)$`, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Resource is publicly accessible. (CWE-1327)"
    }
}