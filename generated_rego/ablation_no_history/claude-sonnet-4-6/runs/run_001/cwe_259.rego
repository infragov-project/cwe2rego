package glitch

import data.glitch_lib

sensitive_name_pattern := "(?i)(.*(?:password|passwd|secret|api_key|apikey|api_secret|access_token|auth_token|connection_string|connection_url|db_url|database_url|master_password|admin_password|root_password|bind_password|keystore_password|truststore_password|client_secret|shared_secret|bootstrap_password|initial_password|default_password|master_user_password|service_account_password|sha512_password|sha256_password).*|^key$)"

is_hardcoded_value(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("(?i).*(\\$\\{|\\$\\(|{{|resolve:|secretsmanager:|key_vault|parameter_store).*", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(sensitive_name_pattern, attr.name)
    is_hardcoded_value(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive attribute fields should not contain literal plaintext credential values. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(sensitive_name_pattern, var.name)
    is_hardcoded_value(var.value)

    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive variable fields should not contain literal plaintext credential values. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match(sensitive_name_pattern, entry.key.value)
    is_hardcoded_value(entry.value)

    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Sensitive hash key contains literal plaintext credential value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, str_node])
    str_node.ir_type == "String"
    regex.match("(?i).*(password|passwd|secret|api_key|apikey|access_token|auth_token)=.+", str_node.value)
    not regex.match("(?i).*(\\$\\{|\\$\\(|{{|resolve:|secretsmanager:|key_vault|parameter_store).*", str_node.value)

    result := {
        "type": "sec_hard_pass",
        "element": str_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Environment variable string contains literal plaintext credential value. (CWE-259)"
    }
}