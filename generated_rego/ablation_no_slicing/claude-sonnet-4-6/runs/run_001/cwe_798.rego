package glitch

import data.glitch_lib

credential_field_pattern := "(?i).*(password|passwd|passphrase|pwd|token|api_key|apikey|private_key|access_key|auth_token|credentials|signing_key|encryption_key|master_key|shared_secret|hmac_secret|client_secret|db_password|database_password|registry_password|webhook_secret|connection_string|database_url|account_key|community_string|auth_passphrase|pem_content|ssh_key|rsa_key|symmetric_key|service_account_key|keystore|truststore|secret|\\bkey\\b|username|\\buser\\b).*"

is_credential_field(name) {
    regex.match(credential_field_pattern, name)
}

is_plain_string_value(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("^(/|[A-Za-z]:\\\\|\\./|~/)", value.value)
    not regex.match("(?i).*\\.(xml|yml|yaml|json|conf|cfg|txt|sh|py|rb|erb|pem|crt|key)$", value.value)
    not regex.match("(?i).*(cn=|dc=|uid=|ou=).*", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_credential_field(node.name)
    is_plain_string_value(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_credential_field(node.name)
    is_plain_string_value(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_credential_field(entry.key.value)
    is_plain_string_value(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    contains(node.value, "-----BEGIN")
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Embedded cryptographic key material detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(".*://[^:@/]+:[^@/]+@.*", node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Connection string with embedded credentials detected. (CWE-798)"
    }
}