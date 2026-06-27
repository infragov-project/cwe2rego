package glitch

import data.glitch_lib

has_wildcard(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == "*"
}

has_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
}

has_delete(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    lower(item.value) == "delete"
}

is_insecure_cors_attr(name, value) {
    name == "allowed_origins"
    has_wildcard(value)
}

is_insecure_cors_attr(name, value) {
    name == "allowed_methods"
    has_wildcard(value)
}

is_insecure_cors_attr(name, value) {
    name == "allowed_methods"
    has_delete(value)
}

is_insecure_cors_attr(name, value) {
    name == "allowed_headers"
    has_wildcard(value)
}

Glitch_Analysis[result] {
    input.path != ""
    walk(input, [_, atomic_unit])
    atomic_unit.ir_type == "AtomicUnit"
    cors_block := atomic_unit.statements[_]
    cors_block.ir_type == "UnitBlock"
    cors_block.type == "block"
    glitch_lib.contains(cors_block.name, "cors")
    cors_block.line > 0
    attr := cors_block.attributes[_]
    is_insecure_cors_attr(attr.name, attr.value)
    result := {
        "type": "sec_s3_unsecured_cors",
        "element": cors_block,
        "path": input.path,
        "description": "S3 Bucket with Unsecured CORS Policy - Overly permissive CORS configuration allows unrestricted cross-origin access, risking data exposure and CSRF attacks. (CWE-942)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node := glitch_lib.all_atomic_units(parent)[_]
    glitch_lib.contains(node.type, "cors")
    attr := node.attributes[_]
    attr.value.ir_type == "Array"
    hash := attr.value.value[_]
    hash.ir_type == "Hash"
    entry := hash.value[_]
    entry.key.ir_type == "String"
    is_insecure_cors_attr(entry.key.value, entry.value)
    result := {
        "type": "sec_s3_unsecured_cors",
        "element": attr,
        "path": parent.path,
        "description": "S3 Bucket with Unsecured CORS Policy - Overly permissive CORS configuration allows unrestricted cross-origin access, risking data exposure and CSRF attacks. (CWE-942)"
    }
}