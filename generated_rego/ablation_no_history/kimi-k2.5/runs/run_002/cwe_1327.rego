package glitch

import data.glitch_lib

unrestricted_bind_values := {"0.0.0.0", "0.0.0.0/0", "*", "::", "::/0", "inaddr_any", "all_interfaces", "any_address", "unspecified", "public", "external", "internet_facing", "open_to_world"}

bind_keywords := {"bind", "binding", "bind_address", "bind_addr", "listen", "listener", "listenaddr", "listen_address", "host", "hostname", "address", "ip_address", "socket_address", "interface", "network_interface", "listening_interface", "listen_port", "endpoint", "ingress", "entrypoint", "frontend", "exposed_port", "published_port", "bindip", "bind_ip", "net_bindip", "net_bind_ip"}

is_unrestricted_value(val) {
    val.ir_type == "String"
    unrestricted_bind_values[lower(val.value)]
}

is_unrestricted_value(val) {
    val.ir_type == "VariableReference"
    unrestricted_bind_values[lower(val.value)]
}

matches_bind_keyword(name) {
    bind_keywords[lower(name)]
}

matches_bind_keyword(name) {
    regex.match("^(ip_)?host(name)?$", lower(name))
}

matches_bind_keyword(name) {
    regex.match("^(ip_)?addr(ess)?$", lower(name))
}

matches_bind_keyword(name) {
    regex.match("^socket_?addr(ess)?$", lower(name))
}

matches_bind_keyword(name) {
    regex.match("^(network_)?interface$", lower(name))
}

matches_bind_keyword(name) {
    regex.match(".*bind.*ip.*", lower(name))
}

matches_bind_keyword(name) {
    regex.match(".*ip.*bind.*", lower(name))
}

check_hash_has_bind_keyword(h, out_key) {
    some kv
    [_, kv] := walk(h.value)
    kv.key.ir_type == "String"
    matches_bind_keyword(kv.key.value)
    out_key = kv.key.value
}

check_hash_unrestricted(h) {
    some kv
    [_, kv] := walk(h.value)
    kv.key.ir_type == "String"
    matches_bind_keyword(kv.key.value)
    is_unrestricted_value(kv.value)
}

check_hash_unrestricted(h) {
    some kv
    [_, kv] := walk(h.value)
    kv.key.ir_type == "VariableReference"
    matches_bind_keyword(kv.key.value)
    is_unrestricted_value(kv.value)
}

check_hash_unrestricted(h) {
    some kv
    [_, kv] := walk(h.value)
    is_unrestricted_value(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    matches_bind_keyword(node.name)
    is_unrestricted_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable configured with unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    matches_bind_keyword(node.name)
    walk(node.value, [_, n])
    is_unrestricted_value(n)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable with nested unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    node.value.ir_type == "Hash"
    check_hash_unrestricted(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Hash within Variable configured with unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    matches_bind_keyword(node.name)
    is_unrestricted_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to listen on all network interfaces without access restrictions. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    matches_bind_keyword(node.name)
    walk(node.value, [_, n])
    is_unrestricted_value(n)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Attribute with nested unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    node.value.ir_type == "Hash"
    check_hash_unrestricted(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Hash attribute configured with unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    matches_bind_keyword(attr.name)
    is_unrestricted_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - AtomicUnit attribute configured with unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    matches_bind_keyword(attr.name)
    walk(attr.value, [_, n])
    is_unrestricted_value(n)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - AtomicUnit attribute with nested unrestricted network binding. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    check_hash_unrestricted(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - AtomicUnit hash attribute configured with unrestricted network binding. (CWE-1327)"
    }
}