package glitch

import data.glitch_lib

password_regex := ".*(password|passwd|pwd|passphrase|activationkey).*"
proxy_password_regex := ".*proxy.*(password|passwd|pwd|passphrase).*"

connection_keywords := {"connectionstring", "connection", "dsn", "uri", "endpoint", "auth", "credentials"}
allow_empty_keywords := {"allowemptypassword", "permitblankpassword", "enablepasswordless", "passwordless", "allowblankpassword"}
password_required_keywords := {"passwordrequired", "requirepassword", "requirepass"}

normalized_name(name) = n {
    s := regex.replace("^\\$", "", name)
    n := lower(regex.replace("[^a-z0-9]", "", s))
}

is_password_name(name) {
    n := normalized_name(name)
    regex.match(password_regex, n)
    not regex.match(proxy_password_regex, n)
}

contains_keyword(n, keywords) {
    kw := keywords[_]
    regex.match(sprintf(".*%s.*", [kw]), n)
}

is_connection_name(name) {
    n := normalized_name(name)
    contains_keyword(n, connection_keywords)
}

is_allow_empty_flag(name) {
    n := normalized_name(name)
    contains_keyword(n, allow_empty_keywords)
}

is_password_required_flag(name) {
    n := normalized_name(name)
    contains_keyword(n, password_required_keywords)
}

empty_value(v) {
    v.ir_type == "String"
    regex.match("^\\s*$", v.value)
}
empty_value(v) {
    v.ir_type == "String"
    lower(v.value) == "null"
}
empty_value(v) {
    v.ir_type == "String"
    v.value == "~"
}
empty_value(v) {
    v.ir_type == "Null"
}
empty_value(v) {
    v.ir_type == "Undef"
}

empty_password_in_connection(v) {
    v.ir_type == "String"
    regex.match("(?i)(password|passwd|pwd|passphrase)\\s*[:=]\\s*(?:\"\"|''|$|[;&])", v.value)
}

flag_true(v) {
    v.ir_type == "Boolean"
    v.value == true
}
flag_true(v) {
    v.ir_type == "String"
    lower(v.value) == "true"
}
flag_true(v) {
    v.ir_type == "String"
    lower(v.value) == "yes"
}
flag_true(v) {
    v.ir_type == "Integer"
    v.value == 1
}
flag_true(v) {
    v.ir_type == "String"
    v.value == "1"
}

flag_false(v) {
    v.ir_type == "Boolean"
    v.value == false
}
flag_false(v) {
    v.ir_type == "String"
    lower(v.value) == "false"
}
flag_false(v) {
    v.ir_type == "String"
    lower(v.value) == "no"
}
flag_false(v) {
    v.ir_type == "Integer"
    v.value == 0
}
flag_false(v) {
    v.ir_type == "String"
    v.value == "0"
}

canonical(name) = c {
    c := regex.replace("^\\$", "", name)
}

is_defined_empty(parent, name) {
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    canonical(v.name) == canonical(name)
    empty_value(v.value)
} else {
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    canonical(a.name) == canonical(name)
    empty_value(a.value)
}

empty_password_reference(parent, val) {
    some vref
    walk(val, [_, vref])
    vref.ir_type == "VariableReference"
    is_password_name(vref.value)
    is_defined_empty(parent, vref.value)
}

pair_key_name(pair) = n {
    pair.key.ir_type == "String"
    n := pair.key.value
} else {
    pair.key.ir_type == "VariableReference"
    n := pair.key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_password_name(kv.name)
    empty_value(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_password_name(kv.name)
    empty_value(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, pair])
    pair.key
    pair.value
    name := pair_key_name(pair)
    is_password_name(name)
    empty_value(pair.value)

    result := {
        "type": "sec_empty_pass",
        "element": pair.value,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_connection_name(kv.name)
    empty_password_in_connection(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_connection_name(kv.name)
    empty_password_in_connection(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, pair])
    pair.key
    pair.value
    name := pair_key_name(pair)
    is_connection_name(name)
    empty_password_in_connection(pair.value)

    result := {
        "type": "sec_empty_pass",
        "element": pair.value,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_allow_empty_flag(kv.name)
    flag_true(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Passwordless authentication enabled - Empty passwords should not be permitted. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_allow_empty_flag(kv.name)
    flag_true(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Passwordless authentication enabled - Empty passwords should not be permitted. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_password_required_flag(kv.name)
    flag_false(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Passwordless authentication enabled - Empty passwords should not be permitted. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_password_required_flag(kv.name)
    flag_false(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Passwordless authentication enabled - Empty passwords should not be permitted. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    empty_password_reference(parent, kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    empty_password_reference(parent, kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, pair])
    pair.key
    pair.value
    empty_password_reference(parent, pair.value)

    result := {
        "type": "sec_empty_pass",
        "element": pair.value,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty. (CWE-258)"
    }
}