package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    (node.type == "KubernetesPod") or (node.type == "DockerContainer") or (node.type == "AWSLambdaFunction") or (node.type == "GCPFunction") or (node.type == "EC2Instance")

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "runAsUser") or (attr.name == "user") or (attr.name == "run_as")
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container or function running as root (UID 0) - Execution with unnecessary privileges detected. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    (node.type == "KubernetesPod") or (node.type == "DockerContainer")

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running with privileged mode enabled - Full host access granted, which is unnecessary in most cases. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "KubernetesPod"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "capabilities") or (attr.name == "securityContext.capabilities")
    attr.value.ir_type == "Hash"
    cap_add := attr.value.value["add"]
    cap_add.ir_type == "Array"
    cap := cap_add.value[_]
    cap.ir_type == "String"
    (cap.value == "CAP_SYS_ADMIN") or (cap.value == "CAP_DAC_OVERRIDE") or (cap.value == "CAP_SYS_RESOURCE") or (cap.value == "CAP_SYS_MODULE") or (cap.value == "CAP_NET_ADMIN")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container granted dangerous Linux capabilities - These capabilities allow privilege escalation and should be avoided unless strictly necessary. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    (node.type == "AWSLambdaFunction") or (node.type == "EC2Instance") or (node.type == "GCPFunction") or (node.type == "AzureFunction")

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    (attr.name == "iam_role") or (attr.name == "service_account") or (attr.name == "instance_role")

    role_value := attr.value
    role_value.ir_type == "String"

    contains(role_value.value, "Administrator") or
    contains(role_value.value, "AdministratorAccess") or
    contains(role_value.value, "Owner") or
    contains(role_value.value, "FullAccess") or
    contains(role_value.value, "PowerUserAccess") or
    contains(role_value.value, "arn:aws:iam::aws:policy/AdministratorAccess") or
    contains(role_value.value, "arn:aws:iam::aws:policy/PowerUserAccess")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service or instance assigned an overly permissive role - Roles with Administrator or Owner privileges should not be used unless absolutely required. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    (node.type == "Dockerfile") or (node.type == "ContainerImage")

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "USER"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Image built with root user - Dockerfile sets USER root, leading to execution as root. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "KubernetesServiceAccount"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "roleRef"
    role_ref := attr.value
    role_ref.ir_type == "Hash"
    role_name := role_ref.value["name"]
    role_name.ir_type == "String"
    (role_name.value == "cluster-admin") or (role_name.value == "admin")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service account bound to cluster-admin or admin role - This grants excessive privileges. (CWE-250)"
    }
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    (node.type == "AWSIAMPolicy") or (node.type == "AzureRBAC") or (node.type == "GCPIAMPolicy")

    attrs := glitch_lib.all_attributes(node)
    stmts := attrs[_]
    stmts.name == "Statement"
    stmts.value.ir_type == "Array"

    statement := stmts.value.value[_]
    statement.ir_type == "Hash"

    effect := statement.value["Effect"]
    effect.ir_type == "String"
    effect.value == "Allow"

    action := statement.value["Action"]
    action.ir_type == "String"
    (action.value == "*") or (action.value == "s3:*") or (action.value == "ec2:*") or (action.value == "lambda:*") or (action.value == "dynamodb:*")

    resource := statement.value["Resource"]
    resource.ir_type == "String"
    (resource.value == "*") or contains(resource.value, "arn:aws::*:*:*:*")

    result := {
        "type": "sec_def_admin",
        "element": statement,
        "path": parent.path,
        "description": "IAM policy with broad allow action and resource - Grants full or wide permissions without restriction. (CWE-250)"
    }
}