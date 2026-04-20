package glitch

import data.glitch_lib

# Helper to check unrestricted IP values
check_unrestricted_ip(value) {
    value.ir_type == "String"
    regex.match("(?i)^(0\\.0\\.0\\.0|::|all|any|0\\.0\\.0\\.0/0|::/0)$", value.value)
} else {
    value.ir_type == "VariableReference"
    regex.match("(?i)^(0\\.0\\.0\\.0|::|all|any|0\\.0\\.0\\.0/0|::/0)$", value.value)
}

# Helper to check overly permissive permissions
check_overly_permissive(value) {
    value.ir_type == "String"
    regex.match("(?i)^(0?777$|public.*read.*write|full.*control|world.*writable)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 777
}

# Rule 1: Detect unrestricted network access in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match("(?i)(bind|listen|address|ip|host|bind-address|bind_address|listen-address|listen_address)$", var.name)
    check_unrestricted_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Unrestricted network access - Variable '%s' set to '%s' allows public access. (CWE-923)", [var.name, var.value.value])
    }
}

# Rule 2: Detect unrestricted network access in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(bind|listen|address|ip|host|bind-address|bind_address|listen-address|listen_address)$", attr.name)
    check_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Unrestricted network access - Attribute '%s' set to '%s' allows public access. (CWE-923)", [attr.name, attr.value.value])
    }
}

# Rule 3: Detect unrestricted network access in hash entries
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    (key.ir_type == "String") | (key.ir_type == "VariableReference")
    key_str := key.value
    regex.match("(?i)(bind|listen|address|ip|host|bind-address|bind_address|listen-address|listen_address)$", key_str)
    check_unrestricted_ip(value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": sprintf("Unrestricted network access - Configuration '%s' set to '%s' allows public access. (CWE-923)", [key_str, value.value])
    }
}

# Rule 4: Detect overly permissive permissions in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match("(?i)^(mode|permission|acl)$", var.name)
    check_overly_permissive(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Incorrect permission assignment - Variable '%s' set to '%s' grants excessive privileges. (CWE-732)", [var.name, var.value.value])
    }
}

# Rule 5: Detect overly permissive permissions in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(mode|permission|acl)$", attr.name)
    check_overly_permissive(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Incorrect permission assignment - Attribute '%s' set to '%s' grants excessive privileges. (CWE-732)", [attr.name, attr.value.value])
    }
}

# Rule 6: Detect overly permissive permissions in hash entries
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    (key.ir_type == "String") | (key.ir_type == "VariableReference")
    key_str := key.value
    regex.match("(?i)^(mode|permission|acl)$", key_str)
    check_overly_permissive(value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": sprintf("Incorrect permission assignment - Configuration '%s' set to '%s' grants excessive privileges. (CWE-732)", [key_str, value.value])
    }
}