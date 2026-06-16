package glitch

import data.glitch_lib

credential_key_pattern := "(?i)\\b(password|secret|key|token|credential|auth|passphrase|secret_key|api_key|sha512_password|uuid|user)\\b"

looks_like_file_path(s) {
    regex.match("^[a-zA-Z]:\\\\", s)
}

looks_like_file_path(s) {
    regex.match("^/", s)
}

looks_like_file_path(s) {
    regex.match("^[./]", s)
}

looks_like_class_name(s) {
    regex.match("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$", s)
}

get_last_segment(name) = segment {
    segments := regex.split("[\\[\\]'.\"]+", name)
    segment := segments[count(segments) - 1]
}

is_credential_value(value) {
    value.ir_type == "String"
    value.value != ""
    not looks_like_file_path(value.value)
    not looks_like_class_name(value.value)
}

check_hash_node(node, parent_path) = result {
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    key.ir_type == "String"
    regex.match(credential_key_pattern, key.value)
    is_credential_value(pair.value)
    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent_path,
        "description": "Hard-coded credential found in IaC script - CWE-798"
    }
}

check_hash_node(node, parent_path) = result {
    node.ir_type == "Hash"
    pair := node.value[_]
    nested_node := pair.value
    result := check_hash_node(nested_node, parent_path)
}

check_hash_node(node, parent_path) = result {
    node.ir_type == "Array"
    element := node.value[_]
    result := check_hash_node(element, parent_path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    last_segment := get_last_segment(variable.name)
    regex.match(credential_key_pattern, last_segment)
    is_credential_value(variable.value)
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded credential found in IaC script - CWE-798"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    last_segment := get_last_segment(attribute.name)
    regex.match(credential_key_pattern, last_segment)
    is_credential_value(attribute.value)
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": "Hard-coded credential found in IaC script - CWE-798"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    result := check_hash_node(node, parent.path)
    result != null
}