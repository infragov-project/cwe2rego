package glitch

import data.glitch_lib

unrestricted_addresses := {"0.0.0.0", "::", "::0", "[::]"}

network_binding_keywords := {"bind", "listen", "host", "address", "ip", "interface", "endpoint", "ingress", "entrypoint", "attach", "associate", "exposed", "published", "mapped", "public", "external", "unrestricted", "open", "addr"}

is_unrestricted(value) {
    value == unrestricted_addresses[_]
}

is_unrestricted_addr(node) {
    node.ir_type == "String"
    is_unrestricted(node.value)
}

normalize_name(raw) = name {
    clean := regex.replace(raw, "^:+", "")
    clean2 := regex.replace(clean, "^'(.*)'$", "$1")
    name := lower(clean2)
}

contains_lower(str, substr) {
    lower_str := lower(str)
    lower_sub := lower(substr)
    contains(lower_str, lower_sub)
}

has_binding_keyword(name) {
    keyword := network_binding_keywords[_]
    contains_lower(name, keyword)
}

extract_key_name(node) = name {
    node.ir_type == "String"
    name := node.value
} else = name {
    node.ir_type == "VariableReference"
    name := normalize_name(node.value)
} else = name {
    node.ir_type == "MethodCall"
    node.method == "[]"
    count(node.args) > 0
    node.args[0].ir_type == "String"
    name := node.args[0].value
} else = name {
    node.ir_type == "MethodCall"
    node.method == "[]"
    count(node.args) > 0
    node.args[0].ir_type == "VariableReference"
    name := normalize_name(node.args[0].value)
} else = "" {
    true
}

all_vars_deep(root) = vars {
    vars := {v | walk(root, [_, v]); v.ir_type == "Variable"}
}

all_attrs_deep(root) = attrs {
    attrs := {a | walk(root, [_, a]); a.ir_type == "Attribute"}
}

is_restricted_string_in_hash(hash_val) {
    walk(hash_val, [_, pair])
    pair.value
    pair.key
    is_unrestricted_addr(pair.value)
}

is_restricted_string_in_array(array_val) {
    walk(array_val, [_, item])
    item.ir_type == "String"
    is_unrestricted(item.value)
}

is_restricted_string_in_value(val) {
    val.ir_type == "String"
    is_unrestricted(val.value)
} else {
    val.ir_type == "Hash"
    is_restricted_string_in_hash(val.value)
} else {
    val.ir_type == "Array"
    is_restricted_string_in_array(val.value)
}

find_unrestricted_hash_key(root) = results {
    results := {r |
        walk(root, [_, pair])
        pair.key
        pair.value
        key_name := extract_key_name(pair.key)
        has_binding_keyword(key_name)
        is_unrestricted_addr(pair.value)
        r := {"found": true, "element": pair.value, "context": key_name}
    }
}

check_variable(var) = results {
    has_binding_keyword(var.name)
    is_restricted_string_in_value(var.value)
    results := {{"found": true, "element": var.value, "context": var.name}}
} else = results {
    var.value.ir_type == "Hash"
    results := find_unrestricted_hash_key(var.value)
} else = {}

check_attribute(attr) = results {
    has_binding_keyword(attr.name)
    is_restricted_string_in_value(attr.value)
    results := {{"found": true, "element": attr.value, "context": attr.name}}
} else = results {
    attr.value.ir_type == "Hash"
    results := find_unrestricted_hash_key(attr.value)
} else = {}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := all_vars_deep(parent)[_]
    found := check_variable(var)[_]
    result := {
        "type": "sec_invalid_bind",
        "element": found.element,
        "path": parent.path,
        "description": sprintf("Unrestricted network binding address detected in variable context '%s' (CWE-1327)", [found.context])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := glitch_lib.all_attributes(au)[_]
    found := check_attribute(attr)[_]
    result := {
        "type": "sec_invalid_bind",
        "element": found.element,
        "path": parent.path,
        "description": sprintf("Unrestricted network binding address detected in resource attribute '%s' (CWE-1327)", [found.context])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    block_unit := parent.unit_blocks[_]
    var := all_vars_deep(block_unit)[_]
    found := check_variable(var)[_]
    result := {
        "type": "sec_invalid_bind",
        "element": found.element,
        "path": parent.path,
        "description": sprintf("Unrestricted network binding address detected in nested variable context '%s' (CWE-1327)", [found.context])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := glitch_lib.all_attributes(au)[_]
    attr.value.ir_type == "Hash"
    found := find_unrestricted_hash_key(attr.value)[_]
    result := {
        "type": "sec_invalid_bind",
        "element": found.element,
        "path": parent.path,
        "description": sprintf("Unrestricted network binding address detected in hash key '%s' (CWE-1327)", [found.context])
    }
}