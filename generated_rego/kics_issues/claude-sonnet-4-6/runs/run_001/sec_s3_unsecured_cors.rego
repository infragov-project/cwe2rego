package glitch

import data.glitch_lib

is_cors_resource_type(t) {
    glitch_lib.contains(t, "cors")
}

value_has_wildcard(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == "*"
}

value_has_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
}

has_destructive_methods(arr_value) {
    arr_value.ir_type == "Array"
    methods := {m.value | m := arr_value.value[_]; m.ir_type == "String"}
    methods["DELETE"]
    methods["PUT"]
}

has_destructive_methods(arr_value) {
    value_has_wildcard(arr_value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_cors_resource_type(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.contains(attr.name, "origin")
    value_has_wildcard(attr.value)

    result := {
        "type": "sec_s3_unsecured_cors",
        "element": attr,
        "path": parent.path,
        "description": "Insecure CORS Policy on Object Storage Bucket - Wildcard allowed origin in CORS configuration enables unauthorized cross-origin requests. (CWE-942)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_cors_resource_type(node.type)

    attr := node.attributes[_]
    attr.value.ir_type == "Array"
    hash_item := attr.value.value[_]
    hash_item.ir_type == "Hash"
    pair := hash_item.value[_]
    pair.key.ir_type == "String"
    glitch_lib.contains(pair.key.value, "method")
    has_destructive_methods(pair.value)

    result := {
        "type": "sec_s3_unsecured_cors",
        "element": attr,
        "path": parent.path,
        "description": "Insecure CORS Policy on Object Storage Bucket - CORS configuration allows destructive HTTP methods which may enable cross-site attacks. (CWE-942)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    stmt := node.statements[_]
    stmt.ir_type == "UnitBlock"
    glitch_lib.contains(stmt.name, "cors")

    attr := stmt.attributes[_]
    value_has_wildcard(attr.value)

    result := {
        "type": "sec_s3_unsecured_cors",
        "element": stmt,
        "path": parent.path,
        "description": "Insecure CORS Policy on Object Storage Bucket - Overly permissive CORS configuration may expose sensitive data or enable cross-site attacks. (CWE-942)"
    }
}