package glitch

import data.glitch_lib

is_bind_name(name) {
    regex.match("(?i).*(bind_addr|bind_ip|bind_address|listen_addr|listen_address|listen_on|ip_address|ip_addr|net_bind|http_addr|https_addr|api_addr|grpc_addr|admin_addr|client_addr|socket_addr|network_addr|source_range|bindip|bindaddr).*", name)
}

is_bind_name(name) {
    regex.match("(?i)(^|[^a-zA-Z0-9])(:?)(ip|addr|address|bind|listen|interface|endpoint|host)([^a-zA-Z0-9]|$)", name)
}

is_wildcard_str(v) {
    v.ir_type == "String"
    wv := {"0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0", "*", "0.0.0.0/0"}
    v.value == wv[_]
}

is_wildcard_str(v) {
    v.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/[0-9]+)?$", v.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_bind_name(v.name)
    is_wildcard_str(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to wildcard addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_bind_name(attr.name)
    is_wildcard_str(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to wildcard addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    not entry.ir_type
    k := entry.key
    val := entry.value
    k.ir_type
    val.ir_type
    is_bind_name(k.value)
    is_wildcard_str(val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to wildcard addresses. (CWE-1327)"
    }
}