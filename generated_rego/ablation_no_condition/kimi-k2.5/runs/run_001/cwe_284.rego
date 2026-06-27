package glitch

import data.glitch_lib
import future.keywords.in

public_access_values := {"0.0.0.0", "0.0.0.0/0", "::/0", "*", "0.0.0.0:0", "0.0.0.0:80", "0.0.0.0:443", "0.0.0.0:8080", "0.0.0.0:3000", "0.0.0.0:5000", "0.0.0.0:8000", "0.0.0.0:9000"}

bind_address_keywords := {"bind", "bindip", "bind_ip", "bindaddress", "bind_address", "bind-address", "listen_addresses", "listenaddress", "listening_address", "host", "network_bind", "ip_bind", "addr", "address", "ip", "interface"}

is_public_access(value) {
    value.ir_type == "String"
    lower(value.value) == public_access_values[_]
}

contains_bind_keyword(str) {
    lower_str := lower(str)
    keyword := bind_address_keywords[_]
    contains(lower_str, keyword)
}

extract_string_from_key(key) = s {
    key.ir_type == "String"
    s := key.value
} else = s {
    key.ir_type == "VariableReference"
    raw := key.value
    s := trim_prefix(raw, ":")
} else = s {
    key.ir_type == "Access"
    key.right.ir_type == "String"
    s := key.right.value
} else = s {
    key.ir_type == "Access"
    key.right.ir_type == "VariableReference"
    raw := key.right.value
    s := trim_prefix(raw, ":")
} else = "" {
    true
}

is_invalid_context(name) {
    lower(name) == "hosts"
}

is_invalid_context(name) {
    lower(name) == "host"
}

hash_has_bind_key_with_public(h) {
    some kv in h.value
    key_str := extract_string_from_key(kv.key)
    not is_invalid_context(key_str)
    contains_bind_keyword(key_str)
    [_, val_node] := walk(kv.value)
    is_public_access(val_node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    not is_invalid_context(node.name)
    contains_bind_keyword(node.name)
    [_, val_node] := walk(node.value)
    is_public_access(val_node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service binding to public address allows connections from any network interface. Bind to specific interfaces to restrict access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    [_, node] := walk(parent)
    node.ir_type == "Attribute"
    not is_invalid_context(node.name)
    contains_bind_keyword(node.name)
    [_, val_node] := walk(node.value)
    is_public_access(val_node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service binding to public address allows connections from any network interface. Bind to specific interfaces to restrict access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    hash_has_bind_key_with_public(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration binds to public address in hash with binding key. Bind to specific interfaces to restrict access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    [_, node] := walk(parent)
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    hash_has_bind_key_with_public(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration binds to public address in hash with binding key. Bind to specific interfaces to restrict access. (CWE-284)"
    }
}