package glitch

import data.glitch_lib

password_name_pattern := "(?i).*(password|passwd|secret|credential|auth_token|db_pass|connection_string|connection_url|db_url|jdbc_url|database_url|dsn|admin_pass|root_pass|master_pass|user_pass|sa_pass|console_pass|account_pass|initial_pass|bootstrap_pass|replication_pass|backup_pass|auth_pass|login_pass|master_user_password|string_data|secret_data|secret_string|secret_value|secret_binary|secret_text).*"

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("(?i)(var\\.|data\\.|ssm:|secretsmanager:|vault:|\\$\\{|\\$\\(|\\{\\{\\s*secret)", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(password_name_pattern, attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. Use a secrets manager or encrypted store instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    regex.match(password_name_pattern, var.name)
    is_hardcoded_string(var.value)

    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. Use a secrets manager or encrypted store instead. (CWE-259)"
    }
}