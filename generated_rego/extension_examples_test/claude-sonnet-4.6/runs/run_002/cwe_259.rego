package glitch

import data.glitch_lib

sensitive_name_pattern := "(?i).*(password|passwd|pwd|passphrase|secret|credential|credentials|auth_token|access_token|bearer_token|api_key|api_secret|access_key|access_secret|sha512_password|md5_password).*"

env_sensitive_pattern := "(?i).*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|CREDENTIALS|AUTH)=[^$({].*"

is_hardcoded_string_value(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(`.*\$\{.*`, value.value)
    not regex.match(`.*\{\{.*`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(sensitive_name_pattern, attr.name)
    is_hardcoded_string_value(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive attribute contains a plain-text literal value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(sensitive_name_pattern, v.name)
    is_hardcoded_string_value(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive variable contains a plain-text literal value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    regex.match(sensitive_name_pattern, pair.key.value)
    is_hardcoded_string_value(pair.value)
    result := {
        "type": "sec_hard_pass",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive key in hash contains a plain-text literal value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    auth_pair := hash_node.value[_]
    auth_pair.key.ir_type == "String"
    regex.match("(?i).*(auth|credential|login|token).*", auth_pair.key.value)
    auth_pair.value.ir_type == "Hash"
    cred_pair := auth_pair.value.value[_]
    cred_pair.key.ir_type == "String"
    cred_pair.key.value == "key"
    is_hardcoded_string_value(cred_pair.value)
    result := {
        "type": "sec_hard_pass",
        "element": cred_pair.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Authentication key field contains a plain-text literal value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, str_node])
    str_node.ir_type == "String"
    regex.match(env_sensitive_pattern, str_node.value)
    result := {
        "type": "sec_hard_pass",
        "element": str_node,
        "path": parent.path,
        "description": "Use of hard-coded password - String contains a sensitive credential as a literal value. (CWE-259)"
    }
}