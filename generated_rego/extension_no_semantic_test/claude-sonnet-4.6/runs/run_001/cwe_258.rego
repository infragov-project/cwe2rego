package glitch

import data.glitch_lib

password_field_pattern := `(?i)(password|passwd|passphrase|pwd|secret_key|_secret$|(?:^|_)pass(?:_|$))`

connection_string_field_pattern := `(?i)(connection_string|connectionstring|dsn|jdbc|database_url|mongo_uri|mongodb_uri|redis_url|broker_url)`

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match(`^\s+$`, value.value)
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_password_field(name) {
    regex.match(password_field_pattern, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    v := variables[_]
    is_password_field(v.name)
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(connection_string_field_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(`(?i)(password=;|pwd=;|://[^:@]*:@)`, attr.value.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings should not have empty password fields. (CWE-258)"
    }
}