package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "principal" or attr.name == "principals" or attr.name == "principal_arn"
    attr.value.ir_type == "String"
    regex.match("^(\\*|0{12}|arn:aws:iam::000000000000:)?$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive principal setting - Wildcard or root account access may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "effect" or attr.name == "permission"
    attr.value.ir_type == "String"
    regex.match("^Allow$", attr.value.value)

    action_attr := {a | a := attrs[_]; a.name == "action"; a.value.ir_type == "String"}
    action_attr.value.value == "*"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcards in action and allow effect may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "allow_public_access" or attr.name == "publicly_accessible" or attr.name == "public_access"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible resource may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "ingress" or attr.name == "egress" or attr.name == "firewall_rule"
    attr.value.ir_type == "Array"
    rules := attr.value.value
    rule := rules[_]

    rule.ir_type == "Hash"
    cidr_attr := {a | a := rule.value; a.name == "cidr"; a.value.ir_type == "String"}
    cidr_attr.value.value == "0.0.0.0/0"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Network rule with 0.0.0.0/0 allows unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "auth" or attr.name == "authentication" or attr.name == "security"
    attr.value.ir_type == "String"
    regex.match("^(none|disabled|open|off)$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication is disabled, leading to potential improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "password" or attr.name == "secret_key" or attr.name == "api_key" or attr.name == "token"
    attr.value.ir_type == "String"
    regex.match("^(admin|password|secret|test|default|123456|qwerty|letmein)$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded or default credential may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "requires_mfa" or attr.name == "mfa_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Multi-factor authentication is not required, weakening identity verification. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "trust_relationship" or attr.name == "assume_role_policy" or attr.name == "condition"
    attr.value.ir_type == "Hash"
    trust := attr.value.value
    trust_principal := {a | a := trust; a.name == "Principal"; a.value.ir_type == "String"}
    regex.match("^\\*$", trust_principal.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Trust relationship allows any entity, leading to improper access control. (CWE-284)"
    }
}