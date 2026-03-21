package glitch

import data.glitch_lib
import future.keywords.in

password_keywords := {"password", "pwd", "pass"}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_password_field(name) {
    some keyword
    keyword in password_keywords
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

is_empty_password_pattern(str) {
    regex.match(`(?i)pwd\s*=\s*;`, str)
} else {
    regex.match(`(?i)password\s*=\s*;`, str)
} else {
    regex.match(`(?i)://[^:]*:@`, str)
}

connection_string_keywords := {"connection_string", "uri", "dsn", "link", "connection"}

is_connection_string_field(name) {
    some keyword
    keyword in connection_string_keywords
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_field(var.name)
    is_empty_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - CWE-258"
    }
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
        "description": "Empty password in configuration file - CWE-258"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_connection_string_field(attr.name)
    attr.value.ir_type == "String"
    is_empty_password_pattern(attr.value.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - CWE-258"
    }
}