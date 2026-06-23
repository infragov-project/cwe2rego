package glitch

import data.glitch_lib
import future.keywords.in

password_indicators := {"password", "passwd", "secret", "token", "key", "credential", "passcode", "passphrase"}

is_empty_value(value) {
    value.ir_type == "String"
    count(trim(value.value, " \t\n\r")) == 0
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

extract_leaf_component(name) = leaf {
    parts := regex.find_all_string_submatch_n(`\['([^']+)'\]$`, name, 1)
    count(parts) > 0
    leaf := lower(parts[0][1])
} else = leaf {
    parts := split(name, ".")
    count(parts) > 0
    leaf := lower(parts[minus(count(parts), 1)])
} else = leaf {
    parts := split(name, "_")
    count(parts) > 0
    leaf := lower(parts[minus(count(parts), 1)])
} else = leaf {
    leaf := lower(name)
}

is_password_field(name) {
    leaf := extract_leaf_component(name)
    indicator := password_indicators[_]
    regex.match(sprintf(".*(^|_|\\.)(%s)($|_|\\.|$).*", [indicator]), leaf)
} else {
    lower_name := lower(name)
    contains(lower_name, "password")
} else {
    lower_name := lower(name)
    contains(lower_name, "secret")
}

is_defaults_path(path) {
    lower_path := lower(path)
    contains(lower_path, "/defaults/")
} else {
    lower_path := lower(path)
    contains(lower_path, "/group_vars/")
} else {
    lower_path := lower(path)
    contains(lower_path, "attributes")
}

is_critical_password(name) {
    lower_name := lower(name)
    critical := {"password", "passwd", "secret", "admin_password", "root_password", "db_password", "user_password"}
    some c in critical
    contains(lower_name, c)
} else {
    leaf := extract_leaf_component(name)
    leaf == "password"
} else {
    leaf := extract_leaf_component(name)
    leaf == "secret"
}

collect_all_keyvalues(parent) = result {
    direct_vars := {kv |
        some var in parent.variables
        kv := {"ir_type": var.ir_type, "name": var.name, "value": var.value, "line": var.line, "code": var.code, "column": var.column, "end_line": var.end_line, "end_column": var.end_column}
    }

    nested_ub_vars := {kv |
        some ub in parent.unit_blocks
        some var in ub.variables
        kv := {"ir_type": var.ir_type, "name": var.name, "value": var.value, "line": var.line, "code": var.code, "column": var.column, "end_line": var.end_line, "end_column": var.end_column}
    }

    nested_ub_attrs := {kv |
        some ub in parent.unit_blocks
        some attr in ub.attributes
        kv := {"ir_type": attr.ir_type, "name": attr.name, "value": attr.value, "line": attr.line, "code": attr.code, "column": attr.column, "end_line": attr.end_line, "end_column": attr.end_column}
    }

    walk_attrs := {kv |
        walk(parent, [_, node])
        node.ir_type == "Attribute"
        kv := {"ir_type": node.ir_type, "name": node.name, "value": node.value, "line": node.line, "code": node.code, "column": node.column, "end_line": node.end_line, "end_column": node.end_column}
    }

    result := direct_vars | nested_ub_vars | nested_ub_attrs | walk_attrs
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_kvs := collect_all_keyvalues(parent)
    kv := all_kvs[_]

    is_empty_value(kv.value)
    is_password_field(kv.name)

    not is_defaults_path(parent.path)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_kvs := collect_all_keyvalues(parent)
    kv := all_kvs[_]

    is_empty_value(kv.value)
    is_critical_password(kv.name)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty or null. (CWE-258)"
    }
}