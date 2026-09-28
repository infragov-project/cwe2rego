package glitch

import data.glitch_lib

sensitive_keyword_pattern := "(?i).*(password|passwd|pwd|secret|api_key|access_token|auth_token|private_key|client_secret|connection_string|db_password|database_url|db_credentials|access_key_id|secret_access_key|subscription_key|account_key|service_account|certificate|ssh_key|rsa_key|passphrase|master_key|encryption_key|shared_secret|truststore|keystore|token|credential).*"

is_sensitive_name(name) {
    regex.match(sensitive_keyword_pattern, name)
}

is_sensitive_name(name) {
    regex.match("(?i)(^|[._-])key$", name)
}

is_sensitive_name(name) {
    regex.match(`(?i)(^|\.)user(name)?$`, name)
}

is_plaintext_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not regex.match("^[/~]", value.value)
    not regex.match("(?i)^[a-z]:\\\\", value.value)
    not regex.match(`(?i)^[a-z]+=[^,]*(,[a-z]+=[^,]*)+$`, value.value)
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, v])
    v.ir_type == "Variable"
    is_sensitive_name(v.name)
    is_plaintext_string(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Hard-coded secret detected - Sensitive credentials should not be hardcoded in IaC scripts. Use secret managers or environment variables instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    is_sensitive_name(attr.name)
    is_plaintext_string(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret detected - Sensitive credentials should not be hardcoded in IaC scripts. Use secret managers or environment variables instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_plaintext_string(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Hard-coded secret detected - Sensitive credentials should not be hardcoded in IaC scripts. Use secret managers or environment variables instead. (CWE-798)"
    }
}