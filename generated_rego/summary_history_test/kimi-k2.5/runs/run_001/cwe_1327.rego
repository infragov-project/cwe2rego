package glitch

import data.glitch_lib

unrestricted_ip_patterns := {"0.0.0.0", "*", "::", "0.0.0.0/0", "0.0.0.0/8"}

binding_keywords := {"listen", "listenaddr", "listen_address", "bind", "bind_addr", "bind_address", "host", "hostname", "interface", "address", "socket", "endpoint", "ip", "bindip", "bind-ip", "bind_address"}

server_keywords := {"server", "service", "daemon", "listener", "ingress", "expose", "exposed", "public", "database", "db_server", "cache", "message_queue"}

network_keywords := {"all_interfaces", "any", "wildcard", "unrestricted", "open", "hostnetwork"}

all_binding_keywords[k] {
    k := binding_keywords[_]
}

all_binding_keywords[k] {
    k := server_keywords[_]
}

all_binding_keywords[k] {
    k := network_keywords[_]
}

contains(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    unrestricted_ip_patterns[value.value]
} else {
    value.ir_type == "String"
    regex.match("^\\[?::\\]?$", value.value)
}

has_binding_keyword(name) {
    name_lower := lower(name)
    contains(name_lower, all_binding_keywords[_])
}

value_has_unrestricted_ip(val) {
    walk(val, [_, node])
    is_unrestricted_ip(node)
}

get_key_string(key) = result {
    key.ir_type == "String"
    result := key.value
} else = result {
    key.ir_type == "VariableReference"
    result := key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.name
    has_binding_keyword(node.name)
    value_has_unrestricted_ip(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable with binding keyword configured with unrestricted IP address (0.0.0.0, *, or ::), which may expose services to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    
    entry := hash_node.value[_]
    key_str := get_key_string(entry.key)
    has_binding_keyword(key_str)
    walk(entry.value, [_, leaf])
    is_unrestricted_ip(leaf)
    
    result := {
        "type": "sec_invalid_bind",
        "element": leaf,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Nested hash key with binding keyword configured with unrestricted IP address (0.0.0.0, *, or ::), which may expose services to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_binding_keyword(attr.name)
    value_has_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Attribute with binding keyword configured with unrestricted IP address (0.0.0.0, *, or ::), which may expose services to unauthorized access. (CWE-1327)"
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
    
    entry := attr.value.value[_]
    key_str := get_key_string(entry.key)
    has_binding_keyword(key_str)
    walk(entry.value, [_, leaf])
    is_unrestricted_ip(leaf)
    
    result := {
        "type": "sec_invalid_bind",
        "element": leaf,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Nested hash in attribute with binding keyword configured with unrestricted IP address (0.0.0.0, *, or ::), which may expose services to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    has_binding_keyword(attr.name)
    value_has_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - UnitBlock attribute with binding keyword configured with unrestricted IP address (0.0.0.0, *, or ::), which may expose services to unauthorized access. (CWE-1327)"
    }
}