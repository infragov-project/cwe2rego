package glitch

import data.glitch_lib

password_field_pattern := "(?i)(.*password.*|.*passwd.*|^pass$|.*_pass$|^pass_.*|.*sha512.*pass.*|.*shared_secret.*|.*pre_shared_key.*|.*bind_pass.*|.*auth_pass.*|.*keystore_pass.*|.*truststore_pass.*)"

env_password_pattern := "(?i).*(?:password|passwd|_pass).*=.+"

auth_parent_pattern := "(?i)(.*auth.*|.*credential.*|.*secret.*)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_field_pattern, attr.name)
    attr.value.ir_type == "String"
    count(attr.value.value) > 0
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(password_field_pattern, v.name)
    v.value.ir_type == "String"
    count(v.value.value) > 0
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match(password_field_pattern, entry.key.value)
    entry.value.ir_type == "String"
    count(entry.value.value) > 0
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    auth_entry := node.value[_]
    auth_entry.key.ir_type == "String"
    regex.match(auth_parent_pattern, auth_entry.key.value)
    auth_entry.value.ir_type == "Hash"
    inner_entry := auth_entry.value.value[_]
    inner_entry.key.ir_type == "String"
    inner_entry.key.value == "key"
    inner_entry.value.ir_type == "String"
    count(inner_entry.value.value) > 0
    result := {
        "type": "sec_hard_pass",
        "element": inner_entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(env_password_pattern, node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}