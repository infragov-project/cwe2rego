package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "secret", "credentials", "credential", "auth_token", "api_key", "key", "token", "pass"}

is_empty_string(value) {
    value.ir_type == "String"
    count(value.value) == 0
}

is_whitespace_only(value) {
    value.ir_type == "String"
    count(value.value) > 0
    regex.match("^[[:space:]]*$", value.value)
}

is_placeholder_value(value) {
    value.ir_type == "String"
    count(value.value) > 0
    lcase := lower(value.value)
    lcase == {"changeme", "default", "admin", "password", "123456", "empty", "nil", "null"}[_]
}

is_null_or_undef(value) {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_risky_empty_value(value) {
    is_empty_string(value)
} else {
    is_whitespace_only(value)
} else {
    is_placeholder_value(value)
} else {
    is_null_or_undef(value)
}

has_password_keyword(name) {
    lname := lower(name)
    kw := password_keywords[_]
    contains(lname, kw)
}

is_api_or_cache_key_field(name) {
    lname := lower(name)
    contains(lname, "api_token")
} else {
    lname := lower(name)
    contains(lname, "cache_access_key")
} else {
    lname := lower(name)
    contains(lname, "cache_secret_key")
} else {
    lname := lower(name)
    contains(lname, "slack_post_username")
} else {
    lname := lower(name)
    contains(lname, "slack_web_hook_url")
}

is_chef_yum_default(name) {
    contains(name, "default['yum']['main']")
    not contains(lower(name), "proxy_password")
}

is_ssl_key_field(name) {
    lname := lower(name)
    contains(lname, "sslclientkey")
}

check_name_and_value(name, value) {
    has_password_keyword(name)
    not is_api_or_cache_key_field(name)
    not is_chef_yum_default(name)
    not is_ssl_key_field(name)
    is_risky_empty_value(value)
}

check_name_and_value(name, value) {
    has_password_keyword(name)
    not is_api_or_cache_key_field(name)
    not is_chef_yum_default(name)
    not is_ssl_key_field(name)
    value.ir_type == "FunctionCall"
    arg := value.args[_]
    check_argument_for_empty_password(arg)
}

check_argument_for_empty_password(arg) {
    arg.ir_type == "VariableReference"
    arg.value == {"mysql_replication_password"}[_]
}

check_argument_for_empty_password(arg) {
    arg.ir_type == "String"
    is_risky_empty_value(arg)
}

check_argument_for_empty_password(arg) {
    arg.ir_type == "VariableReference"
    true
}

collect_leaf_values(node, base_name) = results {
    results = {r |
        walk(node, [path, n])
        count(path) > 0
        is_scalar_value(n)
        key_name := derive_key_name(node, path, base_name)
        r = {"name": key_name, "value": n, "path": path}
    }
}

is_scalar_value(n) {
    n.ir_type == "String"
} else {
    n.ir_type == "Integer"
} else {
    n.ir_type == "Float"
} else {
    n.ir_type == "Boolean"
} else {
    n.ir_type == "Null"
} else {
    n.ir_type == "Undef"
}

derive_key_name(root, path, base_name) = full_name {
    path_keys := [k |
        i := path[_]
        i > 0
        k := get_key_at_path(root, slice(path, 0, i))
    ]
    joined := concat(".", path_keys)
    base_name != ""
    joined != ""
    full_name := concat(".", [base_name, joined])
} else = full_name {
    path_keys := [k |
        i := path[_]
        i > 0
        k := get_key_at_path(root, slice(path, 0, i))
    ]
    joined := concat(".", path_keys)
    base_name == ""
    full_name := joined
} else = base_name {
    base_name != ""
}

get_key_at_path(node, path) = key {
    walk_to_node(node, path, n)
    n.ir_type == "Array"
    n.value[0].ir_type == "String"
    key := n.value[0].value
} else = idx {
    walk_to_node(node, path, n)
    n.ir_type == "Array"
    not n.value[0].ir_type == "String"
    idx := sprintf("%d", [path[count(path) - 1]])
}

walk_to_node(node, [], node)

walk_to_node(node, [head|tail], result) {
    node.ir_type == "Hash"
    node.value[head]
    next := node.value[head]
    walk_to_node(next, tail, result)
}

walk_to_node(node, [head|tail], result) {
    node.ir_type == "Array"
    node.value[head]
    next := node.value[head]
    walk_to_node(next, tail, result)
}

check_nested_structure(node, base_name) {
    leaf_vals := collect_leaf_values(node, base_name)
    lv := leaf_vals[_]
    check_name_and_value(lv.name, lv.value)
}

find_password_variables(ub) = results {
    results = {r |
        pv := ub.variables[_]
        check_name_and_value(pv.name, pv.value)
        r = {"name": pv.name, "value": pv.value, "node": pv}
    }
} else = results {
    results = {r |
        pv := ub.variables[_]
        pv.value.ir_type == "Hash"
        check_nested_structure(pv.value, pv.name)
        r = {"name": pv.name, "value": pv.value, "node": pv}
    }
}

find_password_attributes(ub) = results {
    results = {r |
        pa := ub.attributes[_]
        check_name_and_value(pa.name, pa.value)
        r = {"name": pa.name, "value": pa.value, "node": pa}
    }
} else = results {
    results = {r |
        pa := ub.attributes[_]
        pa.value.ir_type == "Hash"
        check_nested_structure(pa.value, pa.name)
        r = {"name": pa.name, "value": pa.value, "node": pa}
    }
}

find_password_in_atomic_units(ub) = results {
    results = {r |
        au := ub.atomic_units[_]
        pattr := au.attributes[_]
        check_name_and_value(pattr.name, pattr.value)
        r = {"name": pattr.name, "value": pattr.value, "node": pattr}
    }
} else = results {
    results = {r |
        au := ub.atomic_units[_]
        pattr := au.attributes[_]
        pattr.value.ir_type == "Hash"
        check_nested_structure(pattr.value, pattr.name)
        r = {"name": pattr.name, "value": pattr.value, "node": pattr}
    }
}

all_atomic_units_from_statements(node) = aus {
    aus = {au |
        walk(node, [path, n])
        n.ir_type == "AtomicUnit"
        au := n
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pv := find_password_variables(parent)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pv.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pa := find_password_attributes(parent)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pa.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pau := find_password_in_atomic_units(parent)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pau.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    pv := find_password_variables(nested)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pv.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    pa := find_password_attributes(nested)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pa.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    pau := find_password_in_atomic_units(nested)[_]
    result := {
        "type": "sec_empty_pass",
        "element": pau.node,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    stmt := nested.statements[_]
    aus := all_atomic_units_from_statements(stmt)
    au := aus[_]
    attr := au.attributes[_]
    check_name_and_value(attr.name, attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    stmt := nested.statements[_]
    aus := all_atomic_units_from_statements(stmt)
    au := aus[_]
    attr := au.attributes[_]
    attr.value.ir_type == "Hash"
    check_nested_structure(attr.value, attr.name)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty, null, or use default/placeholder values. (CWE-258)"
    }
}