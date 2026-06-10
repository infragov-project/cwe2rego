package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "Action"
    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard action in IAM policy - Using '*' for actions grants excessive privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "Resource"
    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard resource in IAM policy - Using '*' for resources grants excessive privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "Principal"
    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard principal in IAM policy - Using '*' for principal grants excessive privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "Privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running in privileged mode - Running containers with privileged mode grants excessive system capabilities. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "RunAsUser"
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running as root user - Running containers as root user grants excessive privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "PublicAccess"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database or storage with public access - Public access to databases or storage may lead to unauthorized access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "CidrBlock"
    attr.value.ir_type == "String"
    (attr.value.value == "0.0.0.0/0" or attr.value.value == "::/0")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Network security group with open CIDR block - Allowing traffic from any source may lead to unauthorized access. (CWE-250)"
    }
}