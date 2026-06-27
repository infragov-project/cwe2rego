package glitch

import data.glitch_lib

bind_keywords := {"bind", "bind_addr", "bind_address", "binding", "bindTo", "bind_ip", "listen", "listenaddr", "listen_address", "listen_on", "listener", "listening", "host", "host_addr", "hostname", "listen_host", "server_host", "address", "addr", "ip", "ip_address", "ipv4", "ipv6", "inet", "inet_addr", "interface", "iface", "network_interface", "nic", "bind-address"}

context_keywords := {"server", "service", "daemon", "endpoint", "database", "db", "dbms", "sql", "mysql", "mongo", "mongodb", "nosql", "api", "web", "http", "https", "rest", "graphql", "cloud", "instance", "vm", "container", "pod", "kubernetes", "k8s", "docker", "cluster", "ingress", "gateway", "proxy", "load_balancer"}

unrestricted_values := {"0.0.0.0", "::", "::0", "*"}

clean_key(str) = cleaned {
    str1 := replace(str, ":", "")
    str2 := replace(str1, "'", "")
    str3 := replace(str2, "\"", "")
    str4 := replace(str3, "-", "_")
    str5 := replace(str4, "@", "")
    cleaned := lower(str5)
}

matches_bind_keyword(str) {
    some kw
    bind_keywords[kw]
    contains(clean_key(str), kw)
}

has_unrestricted_value(node) {
    node.ir_type == "String"
    some uv
    unrestricted_values[uv]
    node.value == uv
}

has_context_in_scope(scope) {
    walk(scope, [_, node])
    node.ir_type == "String"
    some context
    context_keywords[context]
    contains(lower(node.value), context)
}

is_bind_key(node) {
    node.ir_type == "String"
    matches_bind_keyword(node.value)
} else {
    node.ir_type == "VariableReference"
    matches_bind_keyword(node.value)
}

check_hash_entry(entry) {
    is_bind_key(entry.key)
    has_unrestricted_value(entry.value)
}

check_hash_deep(hash) {
    some entry
    hash.value[entry]
    check_hash_entry(entry)
} else {
    some entry
    hash.value[entry]
    entry.value.ir_type == "Hash"
    check_hash_deep(entry.value)
}

walk_all_nodes(node, nodes) {
    nodes := {n | walk(node, [_, n])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    has_context_in_scope(parent)
    
    nodes := walk_all_nodes(parent, _)
    node := nodes[_]
    
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    check_hash_deep(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to bind to all network interfaces, potentially exposing it to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    has_context_in_scope(parent)
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.name == "override_options"
    var.value.ir_type == "Hash"
    check_hash_deep(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to bind to all network interfaces, potentially exposing it to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    has_context_in_scope(parent)
    
    nodes := walk_all_nodes(parent, _)
    hash := nodes[_]
    
    hash.ir_type == "Hash"
    check_hash_deep(hash)
    
    result := {
        "type": "sec_invalid_bind",
        "element": hash,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to bind to all network interfaces, potentially exposing it to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    has_context_in_scope(parent)
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    matches_bind_keyword(attr.name)
    has_unrestricted_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to bind to all network interfaces, potentially exposing it to unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    has_context_in_scope(parent)
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    matches_bind_keyword(var.name)
    has_unrestricted_value(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service configured to bind to all network interfaces, potentially exposing it to unauthorized access. (CWE-1327)"
    }
}