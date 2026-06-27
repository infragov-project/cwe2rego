package glitch

import data.glitch_lib

# Check for overly permissive access patterns
check_wildcard_access(value) {
    value.ir_type == "String"
    value.value == "*"
}

check_public_access(value) {
    value.ir_type == "String"
    regex.match("(?i)(public|anonymous|unauthenticated|all_users|everyone|anyone|allusers|all_authenticated_users)", value.value)
}

check_open_cidr(value) {
    value.ir_type == "String"
    regex.match("(?i)(0\\.0\\.0\\.0/0|::/0|0\\.0\\.0\\.0)", value.value)
}

check_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    regex.match("(?i)^(false|disabled?|no)$", value.value)
}

check_permission_value(value) {
    value.ir_type == "String"
    regex.match("(?i)(public-read|public-read-write|authenticated-read|bucket-owner-full-control)", value.value)
}

check_admin_privilege(value) {
    value.ir_type == "String"
    regex.match("(?i)(admin|administrator|root|superuser|full_access|all_privileges|unrestricted)", value.value)
}

check_auth_bypass(value) {
    value.ir_type == "String"
    regex.match("(?i)(skip_auth|bypass_auth|auth_disabled|authentication_disabled|no_auth|anonymous|allow_unauthenticated)", value.value)
}

# Collect all string values from nested structures
string_values_from_value(root) = values {
    values = {node.value |
        walk(root, [_, node])
        node.ir_type == "String"
    }
}

integer_values_from_value(root) = values {
    values = {node.value |
        walk(root, [_, node])
        node.ir_type == "Integer"
    }
}

boolean_values_from_value(root) = values {
    values = {node.value |
        walk(root, [_, node])
        node.ir_type == "Boolean"
    }
}

float_values_from_value(root) = values {
    values = {node.value |
        walk(root, [_, node])
        node.ir_type == "Float"
    }
}

# Check if any nested string matches pattern
any_nested_string_matches(root, pattern) {
    vals := string_values_from_value(root)
    val := vals[_]
    regex.match(pattern, val)
}

# Wildcard in access control
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    access_attr_names := {"access", "acl", "policy", "permissions", "access_policy", "access_control", "authorization", "authentication", "auth", "ingress", "egress", "principal", "resource", "action", "trust_policy", "assume_role_policy"}
    access_attr_names[_] == attr.name
    check_wildcard_access(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard (*) used in access control configuration allowing overly broad permissions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    access_attr_names := {"access", "acl", "policy", "permissions", "access_policy", "access_control", "authorization", "authentication", "auth", "ingress", "egress", "principal", "resource", "action", "trust_policy", "assume_role_policy"}
    access_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "^(\\*)$")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard (*) used in access control configuration allowing overly broad permissions. (CWE-284)"
    }
}

# Public access
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    public_attr_names := {"public_access", "public_read", "public_write", "acl", "access_level", "grant", "predefined_acl", "default_object_acl", "grantees"}
    public_attr_names[_] == attr.name
    check_public_access(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Public or anonymous access enabled on resource. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    public_attr_names := {"public_access", "public_read", "public_write", "acl", "access_level", "grant", "predefined_acl", "default_object_acl", "grantees"}
    public_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)(public|anonymous|unauthenticated|all_users|everyone|anyone|allusers|all_authenticated_users)")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Public or anonymous access enabled on resource. (CWE-284)"
    }
}

# Open CIDR
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cidr_attr_names := {"cidr", "cidr_blocks", "source_cidr", "allowed_ips", "allowed_cidrs", "ipv6_cidr_blocks", "source", "destination", "range"}
    cidr_attr_names[_] == attr.name
    check_open_cidr(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Open CIDR block (0.0.0.0/0 or ::/0) allows unrestricted network access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cidr_attr_names := {"cidr", "cidr_blocks", "source_cidr", "allowed_ips", "allowed_cidrs", "ipv6_cidr_blocks", "source", "destination", "range"}
    cidr_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)(0\\.0\\.0\\.0/0|::/0|0\\.0\\.0\\.0)")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Open CIDR block (0.0.0.0/0 or ::/0) allows unrestricted network access. (CWE-284)"
    }
}

# Disabled security
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    disable_attr_names := {"require_authentication", "verify_identity", "identity_verification", "restrict_public_buckets", "block_public_policy", "block_public_access", "uniform_bucket_level_access", "enable_key_rotation"}
    disable_attr_names[_] == attr.name
    check_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Security protection explicitly disabled or set to false. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    disable_attr_names := {"require_authentication", "verify_identity", "identity_verification", "restrict_public_buckets", "block_public_policy", "block_public_access", "uniform_bucket_level_access", "enable_key_rotation"}
    disable_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)^(false|disabled?|no)$")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Security protection explicitly disabled or set to false. (CWE-284)"
    }
}

# Permission values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    perm_attr_names := {"permission", "permissions", "acl", "access_level", "predefined_acl"}
    perm_attr_names[_] == attr.name
    check_permission_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Overly permissive ACL or permission value set on resource. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    perm_attr_names := {"permission", "permissions", "acl", "access_level", "predefined_acl"}
    perm_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)(public-read|public-read-write|authenticated-read|bucket-owner-full-control)")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Overly permissive ACL or permission value set on resource. (CWE-284)"
    }
}

# Admin privileges
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    admin_attr_names := {"privilege", "role", "managed_policy", "permission_boundary", "permissions", "policy_name"}
    admin_attr_names[_] == attr.name
    check_admin_privilege(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Administrative or excessive privileges assigned. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    admin_attr_names := {"privilege", "role", "managed_policy", "permission_boundary", "permissions", "policy_name"}
    admin_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)(admin|administrator|root|superuser|full_access|all_privileges|unrestricted)")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Administrative or excessive privileges assigned. (CWE-284)"
    }
}

# Auth bypass
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    auth_attr_names := {"authentication", "auth", "authorization", "enable_anonymous_access", "allow_unauthenticated", "skip_authorization", "bypass_auth"}
    auth_attr_names[_] == attr.name
    check_auth_bypass(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication bypass or disabled authentication mechanism detected. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    auth_attr_names := {"authentication", "auth", "authorization", "enable_anonymous_access", "allow_unauthenticated", "skip_authorization", "bypass_auth"}
    auth_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)(skip_auth|bypass_auth|auth_disabled|authentication_disabled|no_auth|anonymous|allow_unauthenticated)")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication bypass or disabled authentication mechanism detected. (CWE-284)"
    }
}

# Public exposure
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    exposure_attr_names := {"publicly_accessible", "publicly_routable", "internet_facing", "internet_accessible", "open_to_internet", "expose_publicly"}
    exposure_attr_names[_] == attr.name
    check_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource explicitly configured for public internet exposure without proper restrictions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    exposure_attr_names := {"publicly_accessible", "publicly_routable", "internet_facing", "internet_accessible", "open_to_internet", "expose_publicly"}
    exposure_attr_names[_] == attr.name
    any_nested_string_matches(attr.value, "(?i)^(false|disabled?|no)$")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource explicitly configured for public internet exposure without proper restrictions. (CWE-284)"
    }
}