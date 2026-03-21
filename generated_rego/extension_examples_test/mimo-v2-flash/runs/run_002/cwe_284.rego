package glitch

import data.glitch_lib

# Helper function to check if a value is an overly permissive bind address
is_bind_address(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
} else {
    value.ir_type == "String"
    value.value == "::/0"
} else {
    value.ir_type == "String"
    value.value == "all"
}

# Helper function to check if a variable/attribute name indicates a bind address
is_bind_address_key(name) {
    regex.match("(?i).*bind.*", name)
} else {
    regex.match("(?i).*ip.*", name)
} else {
    regex.match("(?i).*address.*", name)
}

# Rule for detecting bind addresses in Variables (Ansible/Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_bind_address(v.value)
    is_bind_address_key(v.name)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": sprintf("Improper bind address - Variable '%s' is set to '%s', which allows access from any IP. (CWE-284)", [v.name, v.value.value])
    }
}

# Rule for detecting bind addresses in Attributes (Ansible/Chef/Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_bind_address(attr.value)
    is_bind_address_key(attr.name)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Improper bind address - Attribute '%s' is set to '%s', which allows access from any IP. (CWE-284)", [attr.name, attr.value.value])
    }
}

# Rule for detecting bind addresses in Hash values (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "VariableReference"
    is_bind_address_key(kv.key.value)
    is_bind_address(kv.value)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Improper bind address - Hash key '%s' is set to '%s', which allows access from any IP. (CWE-284)", [kv.key.value, kv.value.value])
    }
}

# Rule for detecting bind addresses in Hash with String keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    is_bind_address_key(kv.key.value)
    is_bind_address(kv.value)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Improper bind address - Hash key '%s' is set to '%s', which allows access from any IP. (CWE-284)", [kv.key.value, kv.value.value])
    }
}

# Rule for detecting bind addresses in nested Array elements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    kv := elem.value[_]
    is_bind_address_key(kv.key.value)
    is_bind_address(kv.value)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Improper bind address - Array element hash key '%s' is set to '%s', which allows access from any IP. (CWE-284)", [kv.key.value, kv.value.value])
    }
}