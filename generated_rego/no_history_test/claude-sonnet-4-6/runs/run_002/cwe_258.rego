package glitch

import data.glitch_lib

password_field_pattern := "(?i).*(password|passwd|passphrase|pwd|secret_pass|api_secret|token_secret|shared_secret|credential|bind_pw|auth_pass|db_pass|user_pass|master_pass|root_pass|ldap_pass|encryption_pass|keystore_pass|truststore_pass|login_pass|access_pass|service_pass|broker_pass|cache_pass).*"

is_empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_field_pattern, attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(password_field_pattern, v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ubs := {n | walk(parent, [_, n]); n.ir_type == "UnitBlock"; n != parent}
    ub := ubs[_]
    vars := glitch_lib.all_variables(ub)
    v := vars[_]
    regex.match(password_field_pattern, v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or null values. (CWE-258)"
    }
}