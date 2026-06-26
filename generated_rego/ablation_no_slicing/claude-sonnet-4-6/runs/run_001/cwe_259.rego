package glitch

import data.glitch_lib

password_field_pattern := "(?i)(^key$|.*(password|passwd|passphrase|pwd|secret|credential|db_pass|admin_pass|root_pass|user_pass|master_pass|login_pass|access_pass|service_pass|ldap_bind_pass|mysql_pass|postgres_pass|mongo_pass|redis_pass|mssql_pass|oracle_pass|sa_pass|sudo_pass|console_pass|shell_pass|enable_pass|superuser_pass|sha512_password).*)"

inline_cred_pattern := "(?i).*(password|passwd|pwd|secret|credential)[^=]*=.+"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_field_pattern, attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords and credentials should not be hardcoded as literal values in IaC scripts. Use secret management references instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(password_field_pattern, v.name)
    v.value.ir_type == "String"
    v.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords and credentials should not be hardcoded as literal values in IaC scripts. Use secret management references instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match(password_field_pattern, entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords and credentials should not be hardcoded as literal values in IaC scripts. Use secret management references instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(inline_cred_pattern, node.value)

    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords and credentials should not be hardcoded as literal values in IaC scripts. Use secret management references instead. (CWE-259)"
    }
}