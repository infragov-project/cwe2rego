package glitch

import data.glitch_lib

sensitive_name_pattern := `(?i).*(password|passwd|\bpwd\b|secret|api_key|apikey|api_token|\btoken\b|auth_token|access_token|credential|private_key|priv_key|encryption_key|crypto_key|access_key|secret_key|client_secret|account_key|connection_string|database_url|db_url|admin_password|root_password|signing_key|hmac_key|shared_key|sas_token|subscription_key|service_account_key|keystore|truststore|\bkey\b|username|\buser\b).*`

name_exclusion_pattern := `(?i).*(_xml\b|_cacertfile\b|_objectclass\b|_attribute\b|_tree_dn\b|_dn\b|_file\b|_path\b|_dir\b|_template\b|_enabled_invert\b|_enabled_default\b|_enabled_attribute\b|_allow_create\b|_allow_update\b|_allow_delete\b).*`

pem_pattern := `(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`

is_hardcoded_string(value) {
    value.ir_type == "String"
    not regex.match(`.*\$\{.*\}.*`, value.value)
    not regex.match(`.*\$\(.*\).*`, value.value)
    not regex.match(`(?i).*(var\.|data\.|local\.|resolve:|ref:).*`, value.value)
    not regex.match(`(?i).*(cn=|dc=|ou=|uid=\w).*`, value.value)
}

is_sensitive_name(name) {
    regex.match(sensitive_name_pattern, name)
    not regex.match(name_exclusion_pattern, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type != "BlockExpr"
    is_sensitive_name(node.name)
    is_hardcoded_string(node.value)
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
    node.ir_type == "Variable"
    node.value.ir_type != "BlockExpr"
    is_sensitive_name(node.name)
    is_hardcoded_string(node.value)
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
    node.key.ir_type == "String"
    is_sensitive_name(node.key.value)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node.key,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(pem_pattern, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Embedded cryptographic key material detected in IaC script. (CWE-798)"
    }
}