package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "Action" | attr.name == "Resource")
    attr.value.ir_type == "String"
    (regex.match(".*\\*.*", attr.value.value) | attr.value.value == "AdministratorAccess")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "IAM policy with wildcard or high-privilege actions/resources - Avoid using wildcard permissions or high-privilege actions without justification. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "privileged" | attr.name == "runAsUser" | attr.name == "hostPID" | attr.name == "hostNetwork")
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context - Avoid running containers or VMs with privileged mode unless necessary. (CWE-250)"
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
        "description": "Running as root - Avoid running containers or VMs as root unless necessary. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "cidr_blocks" | attr.name == "source_cidr_blocks" | attr.name == "ingress_cidr_blocks" | attr.name == "egress_cidr_blocks")
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Open network access - Avoid allowing traffic from 0.0.0.0/0 for sensitive ports. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "acl"
    attr.value.ir_type == "String"
    attr.value.value == "public-read-write"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Public storage access - Avoid granting public read-write access to storage buckets. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match(".*(secret|password).*", attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded secret - Avoid hardcoding secrets in IaC scripts. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "roles" | attr.name == "serviceAccount" | attr.name == "service_account")
    attr.value.ir_type == "String"
    (attr.value.value == "owner" | attr.value.value == "editor" | attr.value.value == "AdministratorAccess")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overprivileged service account - Avoid assigning high-privilege roles to service accounts. (CWE-250)"
    }
}