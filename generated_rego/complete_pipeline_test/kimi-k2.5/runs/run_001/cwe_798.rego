package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "token", "key", "api_key", "auth_key", "private_key", "secret_key", "access_key", "signing_key", "credential", "creds", "encryption_key", "decrypt_key", "client_secret", "consumer_secret", "shared_secret", "keystore", "truststore"}

password_keywords := {"password", "passwd", "pwd", "secret", "token", "client_secret", "consumer_secret", "shared_secret"}

is_base64(s) {
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", s)
}

is_hex_key(s) {
    regex.match("^[0-9a-fA-F]{32,}$", s)
}

is_hash_string(s) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", s)
}

looks_like_path(s) {
    regex.match("^[./][^/]*/[^/]+$", s)
}

extract_bracket_components(name) = components {
    matches := regex.find_all_string_submatch_n("\\['([^']+)'\\]", name, -1)
    components := [m[1] | m := matches[_]]
} else = []

extract_key_components(name) = components {
    bracket_comps := extract_bracket_components(name)
    count(bracket_comps) > 0
    components := [lower(comp) | comp := bracket_comps[_]]
} else = components {
    lower_name := lower(name)
    dot_parts := split(lower_name, ".")
    components := [part | 
        d := dot_parts[_]
        split_parts := split(d, "_")
        part := split_parts[_]
    ]
}

has_credential_keyword(name) {
    comps := extract_key_components(name)
    comp := comps[_]
    kw := credential_keywords[_]
    comp == kw
}

has_password_keyword(name) {
    comps := extract_key_components(name)
    comp := comps[_]
    kw := password_keywords[_]
    comp == kw
}

has_store_keyword(name) {
    comps := extract_key_components(name)
    comp := comps[_]
    comp == "keystore"
} else {
    comps := extract_key_components(name)
    comp := comps[_]
    comp == "truststore"
}

is_external_reference(val) {
    val.ir_type == "VariableReference"
} else {
    val.ir_type == "FunctionCall"
} else {
    val.ir_type == "MethodCall"
}

has_any_external_reference(val) {
    walk(val, [_, node])
    is_external_reference(node)
}

is_obfuscated_credential(s) {
    is_base64(s)
} else {
    is_hex_key(s)
} else {
    is_hash_string(s)
}

detect_hardcoded_credential(key, value_node) {
    value_node.ir_type == "String"
    value_str := value_node.value
    value_str != ""
    not looks_like_path(value_str)
    not has_any_external_reference(value_node)
    has_password_keyword(key)
    is_obfuscated_credential(value_str)
} else {
    value_node.ir_type == "String"
    value_str := value_node.value
    value_str != ""
    not looks_like_path(value_str)
    not has_any_external_reference(value_node)
    has_password_keyword(key)
    lower(value_str) == "password"
} else {
    value_node.ir_type == "String"
    value_str := value_node.value
    value_str != ""
    not looks_like_path(value_str)
    not has_any_external_reference(value_node)
    has_store_keyword(key)
} else {
    value_node.ir_type == "String"
    value_str := value_node.value
    value_str != ""
    not looks_like_path(value_str)
    not has_any_external_reference(value_node)
    has_credential_keyword(key)
    is_obfuscated_credential(value_str)
}

get_all_nodes(parent) = nodes {
    nodes := {n |
        walk(parent, [_, n])
        n.ir_type != ""
    }
}

get_all_variables(parent) = vars {
    nodes := get_all_nodes(parent)
    vars := {n |
        n := nodes[_]
        n.ir_type == "Variable"
    }
}

get_all_attributes(parent) = attrs {
    nodes := get_all_nodes(parent)
    attrs := {n |
        n := nodes[_]
        n.ir_type == "Attribute"
    }
}

hash_entry_nodes[node] {
    node.ir_type == "Hash"
}

hash_entry_nodes[child] {
    some n
    hash_entry_nodes[n]
    n.ir_type == "Hash"
    some entry
    entry := n.value[_]
    child := entry.value
}

hash_entries[{"key": k, "value": v, "code": code, "line": line}] {
    some n
    hash_entry_nodes[n]
    n.ir_type == "Hash"
    some entry
    entry := n.value[_]
    k := entry.key.value
    v := entry.value
    code := n.code
    line := n.line
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := get_all_variables(parent)
    some var
    var := vars[_]
    detect_hardcoded_credential(var.name, var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := get_all_attributes(parent)
    some attr
    attr := attrs[_]
    detect_hardcoded_credential(attr.name, attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := get_all_variables(parent)
    some var
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    some entry
    entry := node.value[_]
    detect_hardcoded_credential(entry.key.value, entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": {"ir_type": "Attribute", "name": entry.key.value, "value": entry.value, "line": entry.value.line, "column": entry.value.column, "end_line": entry.value.end_line, "end_column": entry.value.end_column, "code": var.code},
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := get_all_attributes(parent)
    some attr
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    some entry
    entry := node.value[_]
    detect_hardcoded_credential(entry.key.value, entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": {"ir_type": "Attribute", "name": entry.key.value, "value": entry.value, "line": entry.value.line, "column": entry.value.column, "end_line": entry.value.end_line, "end_column": entry.value.end_column, "code": attr.code},
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}