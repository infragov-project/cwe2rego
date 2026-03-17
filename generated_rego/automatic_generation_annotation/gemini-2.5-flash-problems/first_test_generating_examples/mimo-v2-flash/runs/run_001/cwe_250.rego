package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "community.aws.iam_policy"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "policy_document"
    attr.value.ir_type == "String"
    regex.match("(?s).*\"Action\"\\s*:\\s*\"\\*\".*", attr.value.value)
    regex.match("(?s).*\"Resource\"\\s*:\\s*\"\\*\".*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Overly permissive IAM policy with wildcards in Action and Resource. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "community.docker.docker_container"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Privileged container execution - Container running with elevated privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "execute"
    attrs := glitch_lib.all_attributes(node)
    user_attrs := {attr | attr := attrs[_]; attr.name == "user"}
    count(user_attrs) == 0
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Execute resource running as root by default - no user attribute specified. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "sudo"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "commands"
    attr.value.ir_type == "Array"
    some i
    attr.value.value[i].ir_type == "String"
    attr.value.value[i].value == "ALL"
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Sudo resource with ALL commands without restriction. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "sudo::rule"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "cmnd"
    attr.value.ir_type == "Array"
    some i
    attr.value.value[i].ir_type == "String"
    attr.value.value[i].value == "ALL"
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Sudo rule with ALL commands without restriction. (CWE-250)"
    }
}