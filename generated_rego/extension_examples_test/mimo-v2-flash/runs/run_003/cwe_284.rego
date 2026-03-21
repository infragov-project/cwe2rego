package glitch

import data.glitch_lib

bind_keywords := {"ip", "bind", "address", "host", "interface", "listen", "bind-address", "addr", "server", "master"}

contains_keyword(name) {
    lower_name := lower(name)
    keyword := bind_keywords[_]
    contains(lower_name, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    contains_keyword(var.name)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Public bind address - Bind address set to 0.0.0.0. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    contains_keyword(attr.name)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Public bind address - Bind address set to 0.0.0.0. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key := entry.key
    value := entry.value
    walk(value, [_, val_node])
    val_node.ir_type == "String"
    val_node.value == "0.0.0.0"
    key.ir_type == "String"
    contains_keyword(key.value)
    result := {
        "type": "sec_invalid_bind",
        "element": val_node,
        "path": parent.path,
        "description": "Public bind address - Bind address set to 0.0.0.0. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key := entry.key
    value := entry.value
    walk(value, [_, val_node])
    val_node.ir_type == "String"
    val_node.value == "0.0.0.0"
    key.ir_type == "VariableReference"
    contains_keyword(key.value)
    result := {
        "type": "sec_invalid_bind",
        "element": val_node,
        "path": parent.path,
        "description": "Public bind address - Bind address set to 0.0.0.0. (CWE-284)"
    }
}