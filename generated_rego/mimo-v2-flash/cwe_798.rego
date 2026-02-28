package glitch

import data.glitch_lib

sensitive_key_pattern := "(?i)(password|secret|key|token|credential|passphrase|auth|api_key|access_key|secret_key|private_key|client_secret|master_user_password|admin_password)"

user_key_pattern := "(?i)(user|username|owner|admin|account|uid|become_user|remote_user|user_name)"

default_accounts := {"root", "admin", "user", "guest", "anonymous", "administrator", "sa", "oracle", "postgres", "mysql"}

placeholder_passwords := {"changeme", "admin", "password", "letmein", "123456", "qwerty", "password1", "abc123", "welcome", "monkey", "shadow"}

is_placeholder_password(str) {
    regex.match("^(changeme|admin|password|letmein|123456|qwerty|password1|abc123|welcome|monkey|shadow)$", str)
}

is_long_base64_string(str) {
    regex.match("^[a-zA-Z0-9+/]*={0,2}$", str)
    count(str) >= 16
}

is_long_hex_string(str) {
    regex.match("^[a-fA-F0-9]*$", str)
    count(str) >= 16
}

is_sensitive_key(key) {
    regex.match(sensitive_key_pattern, key)
}

is_user_key(key) {
    regex.match(user_key_pattern, key)
}

is_hardcoded_credential(node, key, value) {
    is_sensitive_key(key)
    value.ir_type == "String"
    value.value != ""
    is_placeholder_password(value.value)
}

is_hardcoded_credential(node, key, value) {
    is_sensitive_key(key)
    value.ir_type == "String"
    value.value != ""
    is_long_base64_string(value.value)
}

is_hardcoded_credential(node, key, value) {
    is_sensitive_key(key)
    value.ir_type == "String"
    value.value != ""
    is_long_hex_string(value.value)
}

is_hardcoded_credential(node, key, value) {
    is_user_key(key)
    value.ir_type == "String"
    value.value != ""
    default_accounts[value.value]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    key := node.name
    value := node.value
    is_hardcoded_credential(node, key, value)
    result := {
        "type": "sec_hard_user",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Attribute with sensitive name has a hard-coded string value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    key := node.name
    value := node.value
    is_hardcoded_credential(node, key, value)
    result := {
        "type": "sec_hard_user",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Variable with sensitive name has a hard-coded string value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    is_hardcoded_credential(node, key.value, value)
    result := {
        "type": "sec_hard_user",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Hash key-value pair with sensitive key has a hard-coded string value. (CWE-798)"
    }
}