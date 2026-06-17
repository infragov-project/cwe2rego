package glitch

import data.glitch_lib

wildcard_ip_set := {"0.0.0.0", "::", "0.0.0.0/0", "::/0", "[::]", "*"}

binding_name_pattern := "(?i)(listen[_-]?(addr(ress)?|on|address)|(^|[_\\-:])bind([_\\-]|$)|bind[-_]?(addr(ress)?|address|host|ip)|(^|[_\\-:\\[])addr(ress)?([_\\-\\]\\[]|$)|ip[-_]addr(ress)?|(^|[_\\-:])ip([_\\-]|$)|advertise[-_]addr(ress)?|server[-_]addr(ress)?|network[-_]interface)"

exposure_pattern := "(?i)^(cidr_blocks|source_ranges|allowed_ips|from_ips|ip_ranges|ingress_cidr|egress_cidr|allowed_subnets|permitted_ips)$"

public_access_pattern := "(?i)^(publicly_accessible|public_access|public_ip_enabled|allow_all|open_access|unrestricted|external_access|expose)$"

is_wildcard_ip(value) {
    value.ir_type == "String"
    value.value == wildcard_ip_set[_]
}

array_contains_wildcard(arr_value) {
    arr_value.ir_type == "Array"
    elem := arr_value.value[_]
    elem.ir_type == "String"
    elem.value == wildcard_ip_set[_]
}

key_is_binding(key) {
    key.ir_type == "String"
    regex.match(binding_name_pattern, key.value)
}

key_is_binding(key) {
    key.ir_type == "VariableReference"
    regex.match(binding_name_pattern, key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(binding_name_pattern, attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service configured to accept connections from all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(binding_name_pattern, v.name)
    is_wildcard_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Variable configures binding to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "Hash"
    entry := v.value.value[_]
    key_is_binding(entry.key)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Hash configuration contains binding key with wildcard IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "Hash"
    outer_entry := v.value.value[_]
    outer_entry.value.ir_type == "Hash"
    inner_entry := outer_entry.value.value[_]
    key_is_binding(inner_entry.key)
    is_wildcard_ip(inner_entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": inner_entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Nested hash configuration contains binding key with wildcard IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(exposure_pattern, attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network exposure field set to wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(exposure_pattern, attr.name)
    array_contains_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network exposure field contains wildcard CIDR. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(public_access_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Resource configured as publicly accessible. (CWE-1327)"
    }
}