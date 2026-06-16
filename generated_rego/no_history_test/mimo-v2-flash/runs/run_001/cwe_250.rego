package glitch

import data.glitch_lib

is_overly_permissive(value) {
    value.ir_type == "String"
    regex.match("(?i).*\\*.*", value.value)
} else {
    value.ir_type == "String"
    regex.match("(?i).*(administratoraccess|fullaccess|admin|superuser|root).*", value.value)
} else {
    value.ir_type == "Array"
    element := value.value[_]
    element.ir_type == "String"
    regex.match("(?i).*\\*.*", element.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    # Handle complex values like Sum that may contain strings
    value.ir_type == "Sum"
    contains_string_with_pattern(value, "(?i).*\\*.*")
} else {
    value.ir_type == "Sum"
    contains_string_with_pattern(value, "(?i).*(administratoraccess|fullaccess|admin|superuser|root).*")
}

contains_string_with_pattern(value, pattern) {
    walk(value, [path, node])
    node.ir_type == "String"
    regex.match(pattern, node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"actions", "resources", "policy", "role", "roles"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Violation of least privilege principle (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"privileged", "allowPrivilegeEscalation", "runAsUser"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container configuration detected - Container runs with unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"serviceAccount", "roles", "accessScopes"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive compute instance permissions detected - VM has unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"privileges", "role", "grants"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation detected - Database user has unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"executionRole", "policy", "permissions"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Serverless function over-permissioning detected - Function has unnecessary privileges (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"serviceAccount", "account"}
    allowed_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i).*default.*", attr.value.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Default service account usage detected - Workload uses default account with broad permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"cidr", "ports", "ipRanges"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permissions in security configuration detected - Unnecessary broad network access (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    allowed_attrs := {"user", "remote_user", "command"}
    allowed_attrs[attr.name]
    is_overly_permissive(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root detected - Unnecessary privileged user (CWE-250)"
    }
}