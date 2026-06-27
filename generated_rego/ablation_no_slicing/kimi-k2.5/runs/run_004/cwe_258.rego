package glitch

import data.glitch_lib

password_patterns := {"password", "passwd", "pwd", "secret", "credential", "auth_token", "api_key", "access_key", "secret_key", "private_key", "passphrase", "token", "key"}

is_empty_string(value) {
    value.ir_type == "String"
    trim_space(value.value) == ""
}

is_null_value(value) {
    value.ir_type == "Null"
}

is_undef_value(value) {
    value.ir_type == "Undef"
}

is_empty_value(value) {
    is_empty_string(value)
} else {
    is_null_value(value)
} else {
    is_undef_value(value)
}

is_simple_password_field(name) {
    some pp
    password_patterns[pp]
    lower_name := lower(name)
    lower_name == pp
}

is_complex_password_field(name) {
    some pp
    password_patterns[pp]
    lower_name := lower(name)
    regex.match(sprintf(".*[^a-zA-Z0-9_]?%s[^a-zA-Z0-9_]?.*", [pp]), lower_name)
}

is_password_field(name) {
    is_simple_password_field(name)
} else {
    is_complex_password_field(name)
}

has_disabled_auth_context(node) {
    walk(node, [_, n])
    n.ir_type == "Variable"
    contains(lower(n.name), "auth")
    n.value.ir_type == "Boolean"
    n.value.value == false
}

has_disabled_auth_context(node) {
    walk(node, [_, n])
    n.ir_type == "Attribute"
    contains(lower(n.name), "auth")
    n.value.ir_type == "Boolean"
    n.value.value == false
}

has_disabled_auth_context(node) {
    walk(node, [_, n])
    n.ir_type == "Variable"
    contains(lower(n.name), "enable")
    n.value.ir_type == "Boolean"
    n.value.value == false
}

has_disabled_auth_context(node) {
    walk(node, [_, n])
    n.ir_type == "Attribute"
    contains(lower(n.name), "enable")
    n.value.ir_type == "Boolean"
    n.value.value == false
}

has_test_indicator(node) {
    walk(node, [_, n])
    n.ir_type == "Variable"
    contains(lower(n.name), "test")
}

has_placeholder(value) {
    value.ir_type == "String"
    regex.match(`(?i)(changeme|replace|placeholder|insert|todo|fixme|xxx|hiera|lookup|env)`, value.value)
}

is_cache_credential(name) {
    contains(lower(name), "cache")
}

is_api_token(name) {
    contains(lower(name), "api_token")
}

is_proxy_related(name) {
    contains(lower(name), "proxy")
}

is_ssl_key(name) {
    contains(lower(name), "sslclientkey")
}

has_function_call_value(value) {
    walk(value, [_, n])
    n.ir_type == "FunctionCall"
}

has_var_ref_in_function(value) {
    value.ir_type == "FunctionCall"
    walk(value, [_, n])
    n.ir_type == "VariableReference"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    is_password_field(vars.name)
    is_empty_value(vars.value)
    not has_disabled_auth_context(parent)
    not has_test_indicator(parent)
    not has_placeholder(vars.value)
    not is_cache_credential(vars.name)
    not is_api_token(vars.name)
    not is_proxy_related(vars.name)
    not is_ssl_key(vars.name)
    result := {
        "type": "sec_empty_pass",
        "element": vars,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    unit_blocks := parent.unit_blocks[_]
    attrs := unit_blocks.attributes[_]
    is_password_field(attrs.name)
    is_empty_value(attrs.value)
    not has_disabled_auth_context(parent)
    not has_test_indicator(parent)
    not has_placeholder(attrs.value)
    not is_cache_credential(attrs.name)
    not is_api_token(attrs.name)
    not is_proxy_related(attrs.name)
    not is_ssl_key(attrs.name)
    result := {
        "type": "sec_empty_pass",
        "element": attrs,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)
    not has_disabled_auth_context(parent)
    not has_test_indicator(parent)
    not has_placeholder(attr.value)
    not is_cache_credential(attr.name)
    not is_api_token(attr.name)
    not is_proxy_related(attr.name)
    not is_ssl_key(attr.name)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_password_field(node.name)
    is_empty_value(node.value)
    not has_disabled_auth_context(parent)
    not has_test_indicator(parent)
    not has_placeholder(node.value)
    not is_cache_credential(node.name)
    not is_api_token(node.name)
    not is_proxy_related(node.name)
    not is_ssl_key(node.name)
    not has_function_call_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_password_field(node.name)
    node.value.ir_type == "FunctionCall"
    has_var_ref_in_function(node.value)
    some ref
    walk(node.value, [_, ref])
    ref.ir_type == "VariableReference"
    ref.value == "mysql_replication_password"
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty or null. (CWE-258)"
    }
}