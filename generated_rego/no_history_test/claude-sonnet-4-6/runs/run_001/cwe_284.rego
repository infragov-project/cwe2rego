package glitch

import data.glitch_lib

iam_wildcard_attrs := {"actions", "resources", "principal", "not_principal", "not_actions", "not_resource"}

is_wildcard_value(value) {
    value.ir_type == "String"
    value.value == "*"
}

is_wildcard_value(value) {
    value.ir_type == "String"
    value.value == "*:*"
}

is_wildcard_value(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
}

is_open_cidr(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0/0"
}

is_open_cidr(value) {
    value.ir_type == "String"
    value.value == "::/0"
}

is_open_cidr(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "0.0.0.0/0"
}

is_open_cidr(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "::/0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)

    effect_attr := attrs[_]
    effect_attr.name == "effect"
    effect_attr.value.ir_type == "String"
    lower(effect_attr.value.value) == "allow"

    wild_attr := attrs[_]
    wild_attr.name == iam_wildcard_attrs[_]
    is_wildcard_value(wild_attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": wild_attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard in IAM policy with Allow effect grants excessive privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"publicly_accessible", "public_network_access_enabled", "enable_public_access", "public_ip_enabled", "allow_anonymous", "anonymous_auth_enabled"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is publicly accessible without restriction. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "acl"
    attr.value.ir_type == "String"
    attr.value.value == {"public-read", "public-read-write", "public"}[_]

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource ACL allows public read or write access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Public access block configuration is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"cidr_blocks", "ipv6_cidr_blocks", "source_ranges", "source_address_prefix"}[_]
    is_open_cidr(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network rule allows unrestricted inbound access from any IP address. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 exposes all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 exposes all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"authorization_type", "auth_type"}[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == "NONE"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - API endpoint configured with no authentication. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "verbs"
    is_wildcard_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - RBAC role grants wildcard verb permissions. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"mfa_delete", "mfa_enabled", "require_mfa"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - MFA is disabled, weakening access control enforcement. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "mfa_configuration"
    attr.value.ir_type == "String"
    upper(attr.value.value) == "OFF"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - MFA configuration is set to OFF. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == {"default_action", "default_behavior"}[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == "ALLOW"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Default action is set to ALLOW in firewall or WAF configuration. (CWE-284)"
    }
}