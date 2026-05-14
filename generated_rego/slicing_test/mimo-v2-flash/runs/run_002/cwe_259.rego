package glitch

import data.glitch_lib

sensitive_keys := {"password", "secret", "credential", "token", "key", "passwd", "pwd", "admin_password", "root_password", "default_password", "initial_password"}

is_secure_reference(str) {
    regex.match("(?i).*(secret_manager|vault|aws_secrets_manager|azure_key_vault|gcp_secret_manager|random_password|random_string|ssm_parameter|kms_secret|env:|\\$\\{|\\{\\{).*", str)
}

is_file_path(str) {
    regex.match(".*[/\\\\].*", str)
}

check_hardcoded_value(value) {
    value.ir_type == "String"
    not is_secure_reference(value.value)
    not is_file_path(value.value)
}

check_key_for_sensitive(key) {
    regex.match("(?i).*(password|secret|credential|token|key|passwd|pwd|admin_password|root_password|default_password|initial_password).*", key)
}

check_hash_for_secrets(hash) {
    hash.ir_type == "Hash"
    some k
    k = hash.value[_]
    k.key.ir_type == "String"
    check_key_for_sensitive(k.key.value)
    k.value.ir_type == "String"
    check_hardcoded_value(k.value)
}

check_array_for_secrets(array) {
    array.ir_type == "Array"
    some element
    element = array.value[_]
    element.ir_type == "Hash"
    check_hash_for_secrets(element)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    check_key_for_sensitive(node.name)
    check_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in variable. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    check_hash_for_secrets(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in variable hash. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Array"
    check_array_for_secrets(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in variable array. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    check_key_for_sensitive(node.name)
    check_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in attribute. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    check_hash_for_secrets(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in attribute hash. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Array"
    check_array_for_secrets(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in attribute array. (CWE-259)"
    }
}