package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "kubernetes_pod"

    attrs := glitch_lib.all_attributes(node)
    
    privileged_attr := [a | a := attrs[_]; a.name == "privileged"]
    run_as_user_attr := [a | a := attrs[_]; a.name == "runAsUser"]
    run_as_non_root_attr := [a | a := attrs[_]; a.name == "runAsNonRoot"]
    allow_privilege_escalation_attr := [a | a := attrs[_]; a.name == "allowPrivilegeEscalation"]

    count(privileged_attr) > 0
    privileged_attr[0].value.ir_type == "Boolean"
    privileged_attr[0].value.value == true

    result := {
        "type": "sec_def_admin",
        "element": privileged_attr[0],
        "path": parent.path,
        "description": "Container running with privileged mode enabled - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "kubernetes_pod"

    attrs := glitch_lib.all_attributes(node)
    
    run_as_user_attr := [a | a := attrs[_]; a.name == "runAsUser"]

    count(run_as_user_attr) > 0
    run_as_user_attr[0].value.ir_type == "Integer"
    run_as_user_attr[0].value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": run_as_user_attr[0],
        "path": parent.path,
        "description": "Container running as root user (UID 0) - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "kubernetes_pod"

    attrs := glitch_lib.all_attributes(node)
    
    run_as_non_root_attr := [a | a := attrs[_]; a.name == "runAsNonRoot"]

    count(run_as_non_root_attr) > 0
    run_as_non_root_attr[0].value.ir_type == "Boolean"
    run_as_non_root_attr[0].value.value == false

    result := {
        "type": "sec_def_admin",
        "element": run_as_non_root_attr[0],
        "path": parent.path,
        "description": "Container allows running as root - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "kubernetes_pod"

    attrs := glitch_lib.all_attributes(node)
    
    allow_privilege_escalation_attr := [a | a := attrs[_]; a.name == "allowPrivilegeEscalation"]

    count(allow_privilege_escalation_attr) > 0
    allow_privilege_escalation_attr[0].value.ir_type == "Boolean"
    allow_privilege_escalation_attr[0].value.value == true

    result := {
        "type": "sec_def_admin",
        "element": allow_privilege_escalation_attr[0],
        "path": parent.path,
        "description": "Container allows privilege escalation - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "iam_policy"

    attrs := glitch_lib.all_attributes(node)
    policy_doc_attr := [a | a := attrs[_]; a.name == "policy_document"]

    count(policy_doc_attr) > 0
    policy_doc_attr[0].value.ir_type == "Hash"

    walk(policy_doc_attr[0].value.value, [path, n])
    n.ir_type == "Attribute"
    n.name == "Action"
    n.value.ir_type == "String"
    regex.match(".*\\*.*", n.value.value)

    result := {
        "type": "sec_def_admin",
        "element": policy_doc_attr[0],
        "path": parent.path,
        "description": "IAM policy contains wildcard action - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "iam_policy"

    attrs := glitch_lib.all_attributes(node)
    policy_doc_attr := [a | a := attrs[_]; a.name == "policy_document"]

    count(policy_doc_attr) > 0
    policy_doc_attr[0].value.ir_type == "Hash"

    walk(policy_doc_attr[0].value.value, [path, n])
    n.ir_type == "Attribute"
    n.name == "Resource"
    n.value.ir_type == "String"
    regex.match(".*\\*.*", n.value.value)

    result := {
        "type": "sec_def_admin",
        "element": policy_doc_attr[0],
        "path": parent.path,
        "description": "IAM policy contains wildcard resource - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "compute_instance"

    attrs := glitch_lib.all_attributes(node)
    admin_username_attr := [a | a := attrs[_]; a.name == "admin_username"]

    count(admin_username_attr) > 0
    admin_username_attr[0].value.ir_type == "String"
    regex.match("(?i)^(root|admin)$", admin_username_attr[0].value.value)

    result := {
        "type": "sec_def_admin",
        "element": admin_username_attr[0],
        "path": parent.path,
        "description": "Compute instance running with admin/root username - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "kubernetes_pod"

    attrs := glitch_lib.all_attributes(node)
    automount_attr := [a | a := attrs[_]; a.name == "automountServiceAccountToken"]

    count(automount_attr) > 0
    automount_attr[0].value.ir_type == "Boolean"
    automount_attr[0].value.value == true

    result := {
        "type": "sec_def_admin",
        "element": automount_attr[0],
        "path": parent.path,
        "description": "Pod automatically mounts default service account token - Execution with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "file_resource"

    attrs := glitch_lib.all_attributes(node)
    mode_attr := [a | a := attrs[_]; a.name == "mode"]

    count(mode_attr) > 0
    mode_attr[0].value.ir_type == "String"
    regex.match("(?:^0?777$)|(?:(?:^|(?:ugo)|o|a)\\+[rwx]{3})", mode_attr[0].value.value)

    result := {
        "type": "sec_def_admin",
        "element": mode_attr[0],
        "path": parent.path,
        "description": "File has world-writable/executable permissions - Execution with unnecessary privileges (CWE-250)"
    }
}