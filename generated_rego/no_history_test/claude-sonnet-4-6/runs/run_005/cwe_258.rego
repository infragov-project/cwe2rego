package glitch

import data.glitch_lib

credential_pattern := "(?i).*(password|passwd|passphrase|pwd|db_pass(?:word)?|db_pwd|mysql_pass(?:word)?|postgres_pass(?:word)?|ldap_pass(?:word)?|smtp_pass(?:word)?|ftp_pass(?:word)?|admin_pass(?:word)?|root_pass(?:word)?|master_pass(?:word)?|service_pass(?:word)?|bind_pass(?:word)?|auth_pass(?:word)?|mssql_sa_pass(?:word)?|redis_pass(?:word)?|mongo_pass(?:word)?|user_pass(?:word)?|login_pass(?:word)?|activation_?key|private_?key|api_?key|auth_?key).*"

is_credential_field(name) {
    regex.match(credential_pattern, name)
}

is_empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_field(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - A credential field is assigned an empty or blank value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_credential_field(v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - A credential field is assigned an empty or blank value. (CWE-258)"
    }
}