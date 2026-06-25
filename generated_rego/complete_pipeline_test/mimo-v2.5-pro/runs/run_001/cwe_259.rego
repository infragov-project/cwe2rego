package glitch

import data.glitch_lib

credential_keywords := {
    "password", "passwd", "pwd", "secret", "token",
    "key", "auth", "credential", "passphrase", "apikey"
}

is_credential_name(name) {
    lower_name := lower(name)
    parts := regex.split(`[_.'"#\-\[\]]`, lower_name)
    parts[_] == credential_keywords[_]
}

is_hardcoded_string_value(value) {
    value.ir_type == "String"
    value.value != ""
    not contains_placeholder(value.value)
    not has_variable_references(value)
}

contains_placeholder(str) {
    regex.match(`\$\{.*\}`, str)
} else {
    regex.match(`\{\{.*\}\}`, str)
} else {
    regex.match(`%\{.*\}`, str)
} else {
    regex.match(`\$\(.*\)`, str)
}

has_variable_references(node) {
    walk(node, [_, v])
    v.ir_type == "VariableReference"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_name(var.name)
    is_hardcoded_string_value(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential detected - Avoid storing secrets directly in Infrastructure as Code files. (CWE-259/CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    is_hardcoded_string_value(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential detected - Avoid storing secrets directly in Infrastructure as Code files. (CWE-259/CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_credential_name(entry.key.value)
    is_hardcoded_string_value(entry.value)
    result := {
        "type": "sec_hard_pass",
        "element": entry.key,
        "path": parent.path,
        "description": "Hard-coded credential detected - Avoid storing secrets directly in Infrastructure as Code files. (CWE-259/CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, arr_node])
    arr_node.ir_type == "Array"
    item := arr_node.value[_]
    item.ir_type == "String"
    check_key_value_credential(item.value)
    not has_variable_references(item)
    result := {
        "type": "sec_hard_pass",
        "element": item,
        "path": parent.path,
        "description": "Hard-coded credential detected - Avoid storing secrets directly in Infrastructure as Code files. (CWE-259/CWE-798)"
    }
}

check_key_value_credential(str) {
    regex.match(`=`, str)
    parts := split(str, "=")
    count(parts) >= 2
    key_part := trim(parts[0], " ")
    is_credential_name(key_part)
    value_part := substring(str, count(parts[0]) + 1, -1)
    count(value_part) >= 1
}