package glitch

import data.glitch_lib

is_admin_string(v) {
    v.ir_type == "String"
    regex.match("(?i)^(root|admin|administrator)$", v.value)
}

is_admin_contains(v) {
    v.ir_type == "String"
    regex.match("(?i)(root|admin|administrator|sudo|wheel)", v.value)
}

is_zero_or_root_id(v) {
    v.ir_type == "Integer"
    v.value == 0
}

is_zero_or_root_id(v) {
    v.ir_type == "String"
    v.value == "0"
}

is_zero_or_root_id(v) {
    is_admin_string(v)
}

is_root_home(v) {
    v.ir_type == "String"
    regex.match("^/root(/|$)", v.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    regex.match("(?i)^(user|run_as|become_user)$", attr.name)
    is_admin_string(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "groups"
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    is_admin_contains(elem)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "groups"
    attr.value.ir_type != "Array"
    is_admin_contains(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    regex.match("(?i)^(uid|gid)$", attr.name)
    is_zero_or_root_id(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "home"
    is_root_home(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    regex.match("(?i)(user|account)", node.type)
    attr := node.attributes[_]
    attr.name == "name"
    is_admin_string(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    regex.match("(?i)(user|run_as|become_user|owner)", entry.key.value)
    is_admin_string(entry.value)
    result := {
        "type": "sec_def_admin",
        "element": entry.value,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    regex.match("(?i)(password|pass|secret|credential)", entry.key.value)
    is_admin_contains(entry.value)
    result := {
        "type": "sec_def_admin",
        "element": entry.value,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "password"
    is_admin_contains(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "content"
    is_admin_contains(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by default - Specifying default admin users may violate the principle of least privilege. (CWE-250)"
    }
}