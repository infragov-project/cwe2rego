package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    regex.match("(?i)password|secret|key|credential|auth", var.name)
    var.value.ir_type == "String"
    count(var.value.value) > 0
    result := {
        "type": "sec_invalid_bind",
        "element": var.value,
        "path": parent.path,
        "line": var.value.line,
        "description": "Hardcoded credential in variable. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr
    attr := glitch_lib.all_attributes(parent)[_]
    regex.match("(?i)password|secret|key|credential|auth", attr.name)
    attr.value.ir_type == "String"
    count(attr.value.value) > 0
    result := {
        "type": "sec_invalid_bind",
        "element": attr.value,
        "path": parent.path,
        "line": attr.value.line,
        "description": "Hardcoded credential in attribute. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    key.ir_type == "String"
    regex.match("(?i)password|secret|key|credential|auth", key.value)
    value := pair.value
    value.ir_type == "String"
    count(value.value) > 0
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "line": value.line,
        "description": "Hardcoded credential in hash. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr
    attr := glitch_lib.all_attributes(parent)[_]
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    key.ir_type == "String"
    regex.match("(?i)password|secret|key|credential|auth", key.value)
    value := pair.value
    value.ir_type == "String"
    count(value.value) > 0
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "line": value.line,
        "description": "Hardcoded credential in hash. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    regex.match("(?i)bind|ip|address|host|server|bind-address|bind_address", var.name)
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": var.value,
        "path": parent.path,
        "line": var.value.line,
        "description": "Unrestricted network binding in variable. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr
    attr := glitch_lib.all_attributes(parent)[_]
    regex.match("(?i)bind|ip|address|host|server|bind-address|bind_address", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": attr.value,
        "path": parent.path,
        "line": attr.value.line,
        "description": "Unrestricted network binding in attribute. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    key.ir_type == "String"
    regex.match("(?i)bind|ip|address|host|server|bind-address|bind_address", key.value)
    value := pair.value
    value.ir_type == "String"
    value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "line": value.line,
        "description": "Unrestricted network binding in hash. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr
    attr := glitch_lib.all_attributes(parent)[_]
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    key.ir_type == "String"
    regex.match("(?i)bind|ip|address|host|server|bind-address|bind_address", key.value)
    value := pair.value
    value.ir_type == "String"
    value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "line": value.line,
        "description": "Unrestricted network binding in hash. (CWE-284)"
    }
}