package glitch

import data.glitch_lib

credential_field_pattern := "(?i).*(password|passwd|passphrase|secret|client_secret|auth_password|auth_token|db_password|database_password|root_password|master_password|api_key|api_secret|secret_access_key|access_key_secret|bind_password|ldap_password|keystore_password|truststore_password|bearer_token|access_token|refresh_token|sha512_password).*"

env_inline_pattern := "(?i).*(password|passwd|secret|api_key|auth_token|access_token|refresh_token|bearer_token)=\\S+"

is_safe_reference(value) {
    regex.match("(?i).*(\\$\\{|\\$\\(|ssm:|secretsmanager:|vault:|azurekeyvault:|!Ref|!Sub|\\{\\{|env:|data\\.).*", value)
}

is_placeholder(value) {
    regex.match("(?i)^(changeme|replace|todo|example|placeholder|dummy|xxx+|\\*+|none|null|empty|<[^>]+>)$", value)
}

is_hardcoded_string_value(value) {
    value.ir_type == "String"
    value.value != ""
    not is_safe_reference(value.value)
    not is_placeholder(value.value)
}

is_credential_name(name) {
    regex.match(credential_field_pattern, name)
}

is_credential_name(name) {
    name == "key"
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
        "description": "Use of hard-coded password - Credential fields should not contain literal string values. Use secret managers or variable references instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_credential_name(v.name)
    is_hardcoded_string_value(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Credential fields should not contain literal string values. Use secret managers or variable references instead. (CWE-259)"
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
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Credential fields should not contain literal string values. Use secret managers or variable references instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, str_node])
    str_node.ir_type == "String"
    regex.match(env_inline_pattern, str_node.value)
    not is_safe_reference(str_node.value)
    result := {
        "type": "sec_hard_pass",
        "element": str_node,
        "path": parent.path,
        "description": "Use of hard-coded password in inline environment variable string. (CWE-259)"
    }
}