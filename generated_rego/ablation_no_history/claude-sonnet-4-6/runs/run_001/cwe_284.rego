package glitch

import data.glitch_lib

open_ip_values := {"0.0.0.0/0", "::/0", "0.0.0.0"}

is_open_ip_value(v) {
    v.ir_type == "String"
    v.value == open_ip_values[_]
}

is_bind_or_network_name(name) {
    regex.match("(?i).*(bind|listen|\\bip\\b|addr|address|cidr|source_ranges?|source_address|destination|net_bind).*", name)
}

get_key_str(key) = v {
    key.ir_type == "String"
    v := key.value
}

get_key_str(key) = v {
    key.ir_type == "VariableReference"
    v := key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_bind_or_network_name(v.name)
    is_open_ip_value(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all interfaces or open CIDR. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_bind_or_network_name(attr.name)
    is_open_ip_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all interfaces or open CIDR. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_str := get_key_str(pair.key)
    is_bind_or_network_name(key_str)
    is_open_ip_value(pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all interfaces or open CIDR in hash entry. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i).*(cidr|source_ranges?|source_address|destination).*", attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    elem.value == open_ip_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Unrestricted network access via open CIDR block. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i).*(publicly_accessible|public_access|public_network_access_enabled|internet_facing).*", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is publicly accessible or internet-facing. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    attr.value.value == ["public-read", "public-read-write", "public", "open", "authenticated-read"][_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource ACL allows public or overly broad access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "principal"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard principal grants access to any entity. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(auth_type|authorization_type|authentication)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|anonymous|disabled)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication is disabled or set to none. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i).*(block_public_acls|block_public_policy|restrict_public_buckets|ignore_public_acls|api_key_required|auth_enabled|enable_auth|require_auth).*", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Public access block or authentication control is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i).*(allowed_origins|allow_origins).*", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - CORS policy allows requests from all origins. (CWE-284)"
    }
}