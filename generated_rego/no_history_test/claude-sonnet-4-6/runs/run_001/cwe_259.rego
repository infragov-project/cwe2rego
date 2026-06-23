package glitch

import data.glitch_lib

credential_name_pattern := "(?i)(^key$|.*(password|passwd|secret|token|passphrase|api_key|apikey|private_key|signing_key|encryption_key|access_key|client_secret|shared_secret|jwt_secret|hmac_secret|bind_password|sha512_password|credential|auth_key|bearer).*)"

connection_string_pattern := "(?i).*(connection_string|connectionstring|connection_url|jdbc_url|db_url|dsn|uri|endpoint).*"

embedded_cred_pattern := "(?i).*(password|passwd|pwd|secret|api_key|auth_token|access_key|private_key)=.+"

secret_ref_pattern := "(?i).*(\\$\\{|\\$\\(|\\{\\{|secretRef|vault:|ssm:|parameter_store|secret_manager|keyRef|valueFrom).*"

is_credential_name(name) {
    regex.match(credential_name_pattern, name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(secret_ref_pattern, value.value)
    glitch_lib.traverse_var(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password or secret - Credentials should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_name(var.name)
    is_hardcoded_string(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password or secret in variable - Credentials should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(connection_string_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(embedded_cred_pattern, attr.value.value)
    not regex.match(secret_ref_pattern, attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password or secret in connection string - Credentials should not be embedded inline in connection strings. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_credential_name(entry.key.value)
    is_hardcoded_string(entry.value)
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password or secret in nested map - Credentials should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(embedded_cred_pattern, node.value)
    not regex.match(secret_ref_pattern, node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password or secret embedded in string value - Credentials should not be embedded inline. (CWE-259)"
    }
}