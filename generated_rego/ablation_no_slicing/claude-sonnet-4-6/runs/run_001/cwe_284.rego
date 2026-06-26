package glitch

import data.glitch_lib

is_bind_all_value(val) {
    val.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", val.value)
}

is_bind_related_name(name) {
    regex.match("(?i)(bind|addr|:ip[^a-z_]|:ip$|\\[.*ip.*\\])", name)
}

is_bind_related_hash_key(kv) {
    kv.key.ir_type == "String"
    regex.match("(?i)(bind|addr(ess)?|\\bip\\b)", kv.key.value)
}

is_bind_related_hash_key(kv) {
    kv.key.ir_type == "VariableReference"
    regex.match("(?i)(bind|addr|:ip$|:ip[^a-z_])", kv.key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_bind_related_name(v.name)
    is_bind_all_value(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Unrestricted network binding - Service configured to bind to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_bind_related_name(attr.name)
    is_bind_all_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network binding - Service configured to bind to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    is_bind_related_hash_key(entry)
    is_bind_all_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Unrestricted network binding - Service configured to bind to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(cidr|source_range)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(0\\.0\\.0\\.0/0|::/0)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - CIDR allows traffic from any source. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(action|resource)$", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive access policy - Wildcard in action or resource grants excessive permissions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(publicly_accessible|public_access)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible resource - Resource is exposed to the public internet. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "acl"
    attr.value.ir_type == "String"
    regex.match("(?i)public", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public ACL detected - Resource is configured with a public access control list. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(block_public_acls|block_public_policy|restrict_public_buckets)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access block disabled - Public access restrictions are not enforced. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(auth_type|authorization)$", attr.name)
    attr.value.ir_type == "String"
    upper(attr.value.value) == "NONE"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Service is deployed without identity verification. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(authentication_enabled|require_auth|api_key_required)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication requirement disabled - Authentication is not enforced for access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(mfa_delete|mfa_enabled|require_mfa)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "MFA not enforced - Multi-factor authentication is disabled or not required. (CWE-284)"
    }
}