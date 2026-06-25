package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions?|resources?|principal|permissions?|effect)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(^\\*$|full_access|all_actions|admin_access|superuser|root_access)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive access policy - Wildcard or full access in policy fields grants excessive privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(authentication_required|require_auth|auth_mode|anonymous_access|public_access)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Resources must enforce identity verification. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(auth_type|authorization|auth_mode)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|disabled|no_auth|skip)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled via string value - Resources must enforce identity verification. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(^public$|publicly_accessible|expose_to_internet|allow_all_traffic|anonymous_access)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource publicly exposed - Resources should not be accessible without access restrictions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(^acl$|visibility|public_access)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(public-read|public-write|public_read|public_write|^public$)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public ACL or visibility setting detected - Resources should not be world-readable or world-writable. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(cidr|source_ranges?|ingress|from_cidr|allowed_ips?)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(0\\.0\\.0\\.0/0|::/0)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Open network access detected - CIDR 0.0.0.0/0 allows unrestricted inbound traffic. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(all_ports|allow_all_traffic|unrestricted_ingress|unrestricted_egress|firewall_rule)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "All ports open or all traffic allowed - Network access should be restricted to necessary ports only. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(^members?$|trusted_entities|assume_role_policy|^group$)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(allUsers|allAuthenticatedUsers|^all$|^everyone$|^\\*$)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad role or group membership - Resources should not be accessible to all users. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(^privileged$|org_wide_access|cross_account_access|allow_cross_account)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Privileged or cross-account access enabled - Access should be scoped to necessary principals only. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(logging_enabled|audit_logs|access_logging|monitor_access|cloud_trail|flow_logs|activity_tracking)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Audit logging or monitoring disabled - Access logging must be enabled to maintain accountability. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(audit_logs|cloud_trail|activity_tracking)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(disabled|off|false|none)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Audit logging or monitoring disabled via string value - Access logging must be enabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(encryption_at_rest|ssl_enforcement|require_ssl|tls_required)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Encryption or SSL/TLS disabled - Data stores and communication channels must enforce encryption. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(default_action|default_permissions)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(allow|open)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Default permissive settings detected - Default access should be restrictive, not permissive. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(use_default_policy|inherit_parent_permissions)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Default or inherited permissions in use - Explicit access policies should be defined instead of relying on defaults. (CWE-284)"
    }
}