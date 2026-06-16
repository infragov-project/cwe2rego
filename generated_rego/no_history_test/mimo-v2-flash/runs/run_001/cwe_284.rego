package glitch

import data.glitch_lib

get_leaf_nodes(expr) = leaf_nodes {
    allowed_types := {"String", "Boolean"}
    leaf_nodes := {n | walk(expr, [path, n]); allowed_types[n.ir_type]}
}

is_common_placeholder(str) {
    common_placeholders := {
        "password",
        "secret",
        "example",
        "placeholder",
        "changeme",
        "some_password",
        "some_secret",
        "some_api_key"
    }
    lower_str := lower(str)
    common_placeholders[lower_str]
}

contains_name(name, pattern_set) {
    lower_name := lower(name)
    some pattern
    pattern_set[pattern]
    contains(lower_name, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    leaf_node.ir_type == "String"
    not is_common_placeholder(leaf_node.value)
    contains(lower(leaf_node.value), "administratoraccess")
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Overly Permissive IAM Policy - Contains 'AdministratorAccess' (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    leaf_node.ir_type == "String"
    not is_common_placeholder(leaf_node.value)
    policy_names := {"permission", "action", "resource", "principal", "effect", "policy", "role", "access"}
    contains_name(attribute.name, policy_names)
    contains(leaf_node.value, "*")
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Overly Permissive IAM Policy - Wildcard in policy-related attribute (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    leaf_nodes := get_leaf_nodes(variable.value)
    leaf_node := leaf_nodes[_]
    leaf_node.ir_type == "String"
    not is_common_placeholder(leaf_node.value)
    value_lower := lower(leaf_node.value)
    any({
        contains(value_lower, "public"),
        contains(leaf_node.value, "0.0.0.0/0"),
        contains(leaf_node.value, "0.0.0.0"),
        contains(value_lower, "allusers"),
        contains(value_lower, "allauthenticatedusers")
    })
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Publicly Accessible Resource - Exposed to public internet (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    leaf_node.ir_type == "String"
    not is_common_placeholder(leaf_node.value)
    value_lower := lower(leaf_node.value)
    any({
        contains(value_lower, "public"),
        contains(leaf_node.value, "0.0.0.0/0"),
        contains(leaf_node.value, "0.0.0.0"),
        contains(value_lower, "allusers"),
        contains(value_lower, "allauthenticatedusers")
    })
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Publicly Accessible Resource - Exposed to public internet (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    contains_name(attribute.name, {"authentication"})
    leaf_node.ir_type == "Boolean"
    leaf_node.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Missing Authentication - Authentication disabled (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    contains_name(attribute.name, {"authentication"})
    leaf_node.ir_type == "String"
    contains(lower(leaf_node.value), "disabled")
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Missing Authentication - Authentication disabled (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    contains_name(attribute.name, {"anonymous"})
    leaf_node.ir_type == "Boolean"
    leaf_node.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Missing Authentication - Anonymous access allowed (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    leaf_node.ir_type == "String"
    not is_common_placeholder(leaf_node.value)
    contains_name(attribute.name, {"password", "api_key", "secret_key"})
    leaf_node.value != ""
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Weak Secrets Management - Plaintext secret (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    contains_name(attribute.name, {"logging", "monitoring"})
    leaf_node.ir_type == "Boolean"
    leaf_node.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Inadequate Audit Logging - Logging disabled or monitoring false (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attributes := glitch_lib.all_attributes(atomic_unit)
    attribute := attributes[_]
    leaf_nodes := get_leaf_nodes(attribute.value)
    leaf_node := leaf_nodes[_]
    contains_name(attribute.name, {"logging", "monitoring"})
    leaf_node.ir_type == "String"
    value_lower := lower(leaf_node.value)
    any({
        contains(value_lower, "disabled"),
        contains(value_lower, "false")
    })
    result := {
        "type": "sec_invalid_bind",
        "element": leaf_node,
        "path": parent.path,
        "description": "Inadequate Audit Logging - Logging disabled or monitoring false (CWE-284)"
    }
}