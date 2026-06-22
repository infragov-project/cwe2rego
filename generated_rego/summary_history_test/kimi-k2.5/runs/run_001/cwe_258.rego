package glitch

import data.glitch_lib

is_empty_string(value) {
    value.ir_type == "String"
    value.value == ""
}

is_whitespace_only(value) {
    value.ir_type == "String"
    regex.match("^[ \t\n\r]*$", value.value)
}

is_null_or_undef(value) {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_empty_or_whitespace(value) {
    is_empty_string(value)
} else {
    is_whitespace_only(value)
} else {
    is_null_or_undef(value)
}

contains_credential_pattern(name) {
    lower_name := lower(name)
    regex.match(".*password.*|.*passwd.*|.*pwd.*|.*secret.*|.*credential.*|.*auth_token.*|.*api_key.*|.*access_token.*|.*private_key.*|.*token.*|activationkey", lower_name)
}

is_likely_safe_default(name, path) {
    lower_name := lower(name)
    regex.match(".*cache.*access_key.*|.*cache.*secret_key.*", lower_name)
} else {
    lower_name := lower(name)
    regex.match(".*ssl.*key$|sslclientkey", lower_name)
} else {
    lower_name := lower(name)
    regex.match("^gitlab_runner__api_token$", lower_name)
} else {
    lower(path, path_lower)
    regex.match(".*yum.*attributes.*", path_lower)
    regex.match(".*proxy_password.*", lower(name))
}

is_empty_value(value) {
    is_empty_or_whitespace(value)
} else {
    value.ir_type == "Hash"
    walk(value.value, [_, v])
    v.ir_type == "String"
    v.value == ""
} else {
    value.ir_type == "Array"
    count(value.value) == 0
}

collect_all_attrs_and_vars(node) = items {
    items = {elem |
        walk(node, [_, elem])
        elem.ir_type == "Attribute"
    } | {elem |
        walk(node, [_, elem])
        elem.ir_type == "Variable"
    }
}

is_variable_reference_to_empty(name, search_root) {
    items := collect_all_attrs_and_vars(search_root)
    item := items[_]
    item.name == name
    is_empty_value(item.value)
}

has_empty_arg(args, search_root) {
    arg := args[_]
    is_empty_value(arg)
} else {
    arg := args[_]
    arg.ir_type == "VariableReference"
    is_variable_reference_to_empty(arg.value, search_root)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    
    elem.ir_type == "Attribute"
    contains_credential_pattern(elem.name)
    not is_likely_safe_default(elem.name, parent.path)
    is_empty_value(elem.value)

    result := {
        "type": "sec_empty_pass",
        "element": elem,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    
    elem.ir_type == "Variable"
    contains_credential_pattern(elem.name)
    not is_likely_safe_default(elem.name, parent.path)
    is_empty_value(elem.value)

    result := {
        "type": "sec_empty_pass",
        "element": elem,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    
    elem.ir_type == "Attribute"
    contains_credential_pattern(elem.name)
    not is_likely_safe_default(elem.name, parent.path)
    
    elem.value.ir_type == "FunctionCall"
    has_empty_arg(elem.value.args, parent)

    result := {
        "type": "sec_empty_pass",
        "element": elem,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}