package glitch

import data.glitch_lib

wildcard_grant_attrs := {"actions", "resources", "principal", "federated", "service", "not_actions", "not_resources"}

required_true_attrs := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets", "require_auth", "mfa_enabled", "require_mfa", "enable_rbac", "enable_acl", "enforce_https", "authorization_enabled"}

dangerous_true_attrs := {"publicly_accessible", "open_to_internet", "allow_all_traffic", "disable_iam_auth", "skip_credentials_validation", "cross_account_access"}

auth_disabled_attrs := {"authorization_type", "authentication_type", "auth_type", "authorization", "access_control", "anonymous_auth"}

network_wildcard_attrs := {"cidr", "source", "destination"}

network_wildcard_values := {"0.0.0.0/0", "::/0", "any"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_grant_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard value grants unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == required_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Security access control feature is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dangerous_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured with dangerous or unrestricted public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == auth_disabled_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|disabled|enabled)$", attr.value.value)
    regex.match("(?i)^(none|disabled)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication or authorization is disabled or set to NONE. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == network_wildcard_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == network_wildcard_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Unrestricted network access configured from any source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    regex.match("(?i)^public", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured with a public ACL. (CWE-284)"
    }
}