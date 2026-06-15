package glitch

import data.glitch_lib

hardcoded_keywords := {"password", "passwd", "pwd", "pass", "secret", "apikey", "token", "key", "credential", "auth", "secret_key", "access_key", "private_key", "secret_token", "admin_password", "admin_username", "ssh_private_key", "secret_string", "secret_value", "api_key", "connection_string", "jdbc_url"}

hardcoded_patterns := {"admin", "password123", "tiger", "root", "changeme"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in hardcoded_keywords

    attr.value.ir_type == "String"
    val := attr.value.value
    regex.match("(?i).*password.*|.*secret.*|.*token.*|.*key.*|.*credential.*|.*auth.*", val)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials detected in IaC script - Avoid embedding static secrets in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in hardcoded_keywords

    attr.value.ir_type == "String"
    val := attr.value.value
    val in hardcoded_patterns

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials detected in IaC script - Avoid embedding static secrets in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in hardcoded_keywords

    attr.value.ir_type == "String"
    val := attr.value.value
    regex.match("^[0-9a-fA-F]{32,}$", val)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials detected in IaC script - Avoid embedding static secrets in code. (CWE-798)"
    }
}