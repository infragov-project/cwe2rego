package glitch

import data.glitch_lib

sensitive_name_pattern := `(?i).*(password|passwd|secret|api_key|apikey|api_secret|auth_token|access_token|bearer_token|private_key|client_secret|service_account_key|db_pass|db_password|smtp_password|bind_password|signing_key|encryption_key|hmac_key|tls_key|ssl_key|master_key|credential|connection_string|jdbc_url|username|keystore|truststore).*`

is_sensitive_name(name) {
    regex.match(sensitive_name_pattern, name)
}

is_safe_value(v) {
    regex.match(`(?i)(\$\{|\$\(|\{\{|vault:|ssm:|secretsmanager:|ref:)`, v)
}

is_safe_value(v) {
    regex.match(`^\$[A-Za-z_]`, v)
}

is_safe_value(v) {
    regex.match(`^[a-zA-Z][a-zA-Z0-9]*=[^,\s]+,`, v)
}

is_safe_value(v) {
    regex.match(`^/`, v)
}

is_plain_literal(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_safe_value(value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_name(v.name)
    is_plain_literal(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials in variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_plain_literal(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_plain_literal(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`-----BEGIN.*(PRIVATE KEY|CERTIFICATE)-----`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Embedded cryptographic key material detected inline. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@/\s]+:[^@/\s]+@`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Connection string with embedded credentials detected. (CWE-798)"
    }
}