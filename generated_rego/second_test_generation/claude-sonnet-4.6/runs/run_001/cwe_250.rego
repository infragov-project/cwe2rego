package glitch

import data.glitch_lib

dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "DAC_READ_SEARCH", "CHOWN", "FOWNER"}

is_truthy(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_truthy(value) {
    value.ir_type == "String"
    regex.match("(?i)^(yes|true|1)$", value.value)
}

is_permissive_mode(value) {
    value.ir_type == "String"
    regex.match("^0?777$|^0?666$", value.value)
}

is_permissive_mode(value) {
    value.ir_type == "Integer"
    value.value == 777
}

has_safe_become_user(parent) {
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "become_user"
    attr.value.ir_type == "String"
    attr.value.value != "root"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "privileged"
    is_truthy(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running in privileged mode. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.value == "privileged"
    pair.value.ir_type == "Boolean"
    pair.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "Container running in privileged mode inside nested definition. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.value == "allowPrivilegeEscalation"
    pair.value.ir_type == "Boolean"
    pair.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "allowPrivilegeEscalation set to true. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.value == "runAsNonRoot"
    pair.value.ir_type == "Boolean"
    pair.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "runAsNonRoot set to false - container may run as root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.value == "runAsUser"
    pair.value.ir_type == "Integer"
    pair.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "runAsUser set to 0 (root). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "mode"
    is_permissive_mode(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file mode set on resource. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, outer_hash])
    outer_hash.ir_type == "Hash"
    sc_pair := outer_hash.value[_]
    sc_pair.key.value == "securityContext"
    sc_pair.value.ir_type == "Hash"
    caps_pair := sc_pair.value.value[_]
    caps_pair.key.value == "capabilities"
    caps_pair.value.ir_type == "Hash"
    add_pair := caps_pair.value.value[_]
    add_pair.key.value == "add"
    add_pair.value.ir_type == "Array"
    elem := add_pair.value.value[_]
    elem.ir_type == "String"
    dangerous_caps[elem.value]
    result := {
        "type": "sec_def_admin",
        "element": sc_pair.key,
        "path": parent.path,
        "description": "Dangerous Linux capability granted in securityContext. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    regex.match("(?i)^name:?$", pair.key.value)
    pair.value.ir_type == "String"
    regex.match("(?i)^cluster[-_]admin$", pair.value.value)
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "Binding to cluster-admin role grants excessive privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "become"
    is_truthy(attr.value)
    not has_safe_become_user(parent)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Task uses become without specifying a non-root become_user. (CWE-250)"
    }
}