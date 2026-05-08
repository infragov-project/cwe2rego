package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "secret", "key", "token", "credential", "pwd", "pass"}

weak_passwords := {"admin", "password", "changeme", "123456", "letmein", "tiger", "default", "root", "toor", "admin123", "pass", "secret"}

is_password_key(key) {
    regex.match("(?i)(password|passwd|secret|key|token|credential|pwd|pass)", key)
}

find_passwords_in_node(node) = passwords {
    passwords := {pwd |
        walk(node, [path, n])
        n.ir_type == "String"
        some i
        path[count(path) - 1] == "key"
        key_node := object.get(node, array.slice(path, 0, count(path) - 1), {})
        key_node.ir_type == "String"
        is_password_key(key_node.value)
        pwd := n.value
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_key(var.name)
    var.value.ir_type == "String"
    var.value.value != ""
    not contains(var.value.value, "/")
    not contains(var.value.value, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded password in variable %v", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_key(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    not contains(attr.value.value, "/")
    not contains(attr.value.value, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded password in attribute %v", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_key(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    not contains(attr.value.value, "/")
    not contains(attr.value.value, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded password in resource attribute %v", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    passwords := find_passwords_in_node(var.value)
    count(passwords) > 0
    password := passwords[_]
    password != ""
    not contains(password, "/")
    not contains(password, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded password in nested structure of variable %v", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    passwords := find_passwords_in_node(attr.value)
    count(passwords) > 0
    password := passwords[_]
    password != ""
    not contains(password, "/")
    not contains(password, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded password in nested structure of attribute %v", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    passwords := find_passwords_in_node(attr.value)
    count(passwords) > 0
    password := passwords[_]
    password != ""
    not contains(password, "/")
    not contains(password, "\\")
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded password in nested structure of resource attribute %v", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_key(var.name)
    var.value.ir_type == "String"
    var.value.value != ""
    lower_val := lower(var.value.value)
    weak_passwords[_] == lower_val
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded weak password in variable %v", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_key(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    lower_val := lower(attr.value.value)
    weak_passwords[_] == lower_val
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded weak password in attribute %v", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_key(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    lower_val := lower(attr.value.value)
    weak_passwords[_] == lower_val
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded weak password in resource attribute %v", [attr.name])
    }
}