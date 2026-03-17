package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    kv.key.value == "mode"
    kv.value.ir_type == "String"
    regex.match("0?777|ugo\\+rwx|a\\+rwx", kv.value.value)
    result := {
        "type": "sec_def_admin",
        "element": kv.value,
        "path": parent.path,
        "description": "Excessive file system permissions - Using wide permissions like 777 or similar. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some i
    atomic_unit := atomic_units[i]
    attrs := glitch_lib.all_attributes(atomic_unit)
    some j
    attr := attrs[j]
    attr.name == "mode"
    attr.value.ir_type == "String"
    regex.match("0?777|ugo\\+rwx|a\\+rwx", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file system permissions - Using wide permissions like 777 or similar. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    kv.key.value == "priv"
    kv.value.ir_type == "String"
    regex.match(".*\\*\\..*:ALL.*", kv.value.value)
    result := {
        "type": "sec_def_admin",
        "element": kv.value,
        "path": parent.path,
        "description": "Database and storage over-permissions - Using GRANT ALL or public access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    kv.key.value == "src"
    kv.value.ir_type == "String"
    kv.value.value == "0.0.0.0/0"
    result := {
        "type": "sec_def_admin",
        "element": kv.value,
        "path": parent.path,
        "description": "Network exposure beyond requirements - Using 0.0.0.0/0 CIDR block. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    kv.key.value == "zone"
    kv.value.ir_type == "String"
    kv.value.value == "public"
    result := {
        "type": "sec_def_admin",
        "element": kv.value,
        "path": parent.path,
        "description": "Network exposure beyond requirements - Using public zone. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some i
    atomic_unit := atomic_units[i]
    atomic_unit.type == "exec"
    attrs := glitch_lib.all_attributes(atomic_unit)
    some j
    attr := attrs[j]
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": atomic_unit,
        "path": parent.path,
        "description": "Resource-specific over-privileging - Using root user in exec. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some i
    atomic_unit := atomic_units[i]
    atomic_unit.type == "execute"
    attrs := glitch_lib.all_attributes(atomic_unit)
    some j
    attr := attrs[j]
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": atomic_unit,
        "path": parent.path,
        "description": "Resource-specific over-privileging - Using root user in execute. (CWE-250)"
    }
}