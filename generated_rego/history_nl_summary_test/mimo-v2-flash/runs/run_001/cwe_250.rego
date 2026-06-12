package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)action|permission|resource", attr.name)
    glitch_lib.traverse(attr.value, "*")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "IAM policy with excessive permissions - Wildcard (*) in permissions may grant unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container with privileged mode enabled - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "runAsUser"
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running as root - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)ingress|egress", attr.name)
    glitch_lib.traverse(attr.value, "0.0.0.0/0")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Network rule with open IP range - This may expose services unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)ingress|egress", attr.name)
    glitch_lib.traverse(attr.value, "::/0")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Network rule with open IP range - This may expose services unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "public"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Storage with public access - This may expose data unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "publiclyAccessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Storage with public access - This may expose data unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "remote_user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)command", attr.name)
    glitch_lib.traverse(attr.value, "(?i).*root@.*")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command executed as root user - This may allow unnecessary privileges. (CWE-250)"
    }
}