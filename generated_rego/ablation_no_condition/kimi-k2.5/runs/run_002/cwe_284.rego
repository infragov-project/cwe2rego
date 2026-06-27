package glitch

import data.glitch_lib
import future.keywords

check_world_writable_permission(value) {
    value.ir_type == "String"
    regex.match("(?i)(^0?777$|^0?775$|^(?:ugo|[og]|a)\\+w|a\\+rwx)", value.value)
}

check_world_writable_permission(value) {
    value.ir_type == "Integer"
    value.value == 511
}

check_world_writable_permission(value) {
    value.ir_type == "Integer"
    value.value == 509
}

check_world_writable_permission(value) {
    value.ir_type == "Integer"
    value.value == 508
}

check_insecure_bind_pattern(value) {
    value.ir_type == "String"
    regex.match("(?i)^(\\*|0\\.0\\.0\\.0|::|all|any)$", value.value)
}

bind_related_key_patterns := {"ip", "bind", "listen", "address", "host", "interface", "source", "destination", "cidr", "range", "from", "to", "addr"}

is_bind_related_key(key_val) {
    key_val.ir_type == "String"
    lower_key := lower(key_val.value)
    some pattern in bind_related_key_patterns
    contains(lower_key, pattern)
}

is_bind_related_key(key_val) {
    key_val.ir_type == "VariableReference"
    lower_key := lower(key_val.value)
    some pattern in bind_related_key_patterns
    contains(lower_key, pattern)
}

is_bind_related_attr(name) {
    lower_name := lower(name)
    some pattern in {"bind", "listen", "address", "ip", "host", "interface", "source", "destination", "cidr", "range", "addr"}
    contains(lower_name, pattern)
}

found_in_hash[found_value] {
    some hash_node in {node | walk(input, [_, node]); node.ir_type == "Hash"}
    some pair in hash_node.value
    is_bind_related_key(pair.key)
    check_insecure_bind_pattern(pair.value)
    found_value := pair.value
}

found_in_hash[found_value] {
    some hash_node in {node | walk(input, [_, node]); node.ir_type == "Hash"}
    some pair in hash_node.value
    pair.value.ir_type == "Hash"
    some inner_pair in pair.value.value
    is_bind_related_key(inner_pair.key)
    check_insecure_bind_pattern(inner_pair.value)
    found_value := inner_pair.value
}

found_in_hash[found_value] {
    some hash_node in {node | walk(input, [_, node]); node.ir_type == "Hash"}
    some pair in hash_node.value
    pair.value.ir_type == "Array"
    some elem in pair.value.value
    check_insecure_bind_pattern(elem)
    found_value := elem
}

found_in_array[found_value] {
    some array_node in {node | walk(input, [_, node]); node.ir_type == "Array"}
    some elem in array_node.value
    check_insecure_bind_pattern(elem)
    found_value := elem
}

found_in_array[found_value] {
    some array_node in {node | walk(input, [_, node]); node.ir_type == "Array"}
    some elem in array_node.value
    elem.ir_type == "Hash"
    some pair in elem.value
    is_bind_related_key(pair.key)
    check_insecure_bind_pattern(pair.value)
    found_value := pair.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    is_bind_related_attr(var.name)
    check_insecure_bind_pattern(var.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Resource bound to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    var.value.ir_type == "Hash"
    some found in found_in_hash

    result := {
        "type": "sec_invalid_bind",
        "element": found,
        "path": parent.path,
        "description": "Improper Access Control - Hash configuration contains binding to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    var.value.ir_type == "Array"
    some found in found_in_array

    result := {
        "type": "sec_invalid_bind",
        "element": found,
        "path": parent.path,
        "description": "Improper Access Control - Array configuration contains binding to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_bind_related_attr(attr.name)
    check_insecure_bind_pattern(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource bound to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "Hash"
    some found in found_in_hash

    result := {
        "type": "sec_invalid_bind",
        "element": found,
        "path": parent.path,
        "description": "Improper Access Control - Hash configuration contains binding to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "Array"
    some found in found_in_array

    result := {
        "type": "sec_invalid_bind",
        "element": found,
        "path": parent.path,
        "description": "Improper Access Control - Array configuration contains binding to all interfaces (0.0.0.0, *, ::, all) allowing unauthorized access from any network source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    regex.match("(?i)(file|directory|folder|chmod|filesystem)", node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "mode"
    check_world_writable_permission(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - World-writable permissions allow unauthorized actors to modify resources. (CWE-284)"
    }
}