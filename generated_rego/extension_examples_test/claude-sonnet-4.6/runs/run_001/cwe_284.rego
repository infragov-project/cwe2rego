package glitch

import data.glitch_lib

wildcard_access_attrs := {
    "action", "actions", "resource", "resources", "principal", "principals",
    "permissions", "trusted_entities", "trusted_accounts"
}

security_disabled_attrs := {
    "authentication_enabled", "auth_enabled", "require_auth", "enable_rbac",
    "rbac_enabled", "api_key_required", "block_public_acls", "block_public_policy",
    "restrict_public_buckets", "require_authorization"
}

insecure_enabled_attrs := {
    "anonymous_auth", "anonymous_access", "allow_privilege_escalation",
    "run_as_root", "insecure", "skip_verification", "skip_auth",
    "publicly_accessible", "allow_all_inbound", "allow_all_outbound",
    "access_control_disabled", "disable_authorization", "expose"
}

no_auth_attr_names := {"authorization_type", "auth_type", "authentication"}
role_attr_names := {"role", "roles"}
cors_attr_names := {"allow_origins", "allowed_origins", "cors_origins"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_access_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive wildcard access control - Using '*' grants unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_access_attrs[_]
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    item.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive wildcard in array access control - Using '*' grants unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == security_disabled_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Security control disabled - Authentication or access control features are turned off. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_enabled_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Insecure access feature enabled - Resource is publicly accessible or privilege escalation is allowed. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`^(0\.0\.0\.0(/0)?|::/0)$`, node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Open network access - Address 0.0.0.0 or CIDR 0.0.0.0/0 allows unrestricted network access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(`(?i)^public(-read(-write)?)?$`, attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public resource configured - Resource ACL allows public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == no_auth_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(`(?i)^none$`, attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "No authorization configured - Authorization type is set to NONE. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == role_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(`(?i)(admin|owner|superuser|root|cluster-admin)`, attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "High privilege role assigned - Admin or root roles may grant excessive permissions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cors_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "CORS wildcard origin configured - Allowing all origins may expose sensitive resources. (CWE-284)"
    }
}