package glitch

import data.glitch_lib

check_insecure_acl(node) {
    node.ir_type == "String"
    regex.match("(?i)(?:public|allusers|authenticatedusers|everyone)", node.value)
}

check_missing_auth(node) {
    node.ir_type == "String"
    regex.match("(?i)(?:none|disabled|false|no|anonymous)", node.value)
} else {
    node.ir_type == "Boolean"
    node.value == false
}

check_open_network_access(node) {
    node.ir_type == "String"
    regex.match("^(?:0\\.0\\.0\\.0/0|::/0|0\\.0\\.0\\.0)$", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_name_lower := lower(attr.name)
    acl_attrs := {"acl", "access", "permission", "grants", "grant"}
    auth_attrs := {"authentication", "auth", "auth_enabled", "require_auth"}
    network_attrs := {"cidr", "source_ip", "ip_range", "allowed_hosts", "ingress_cidr"}

    attr_name_lower == acl_attrs[_]
    check_insecure_acl(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Insecure ACL configuration allowing overly broad access to resources. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_name_lower := lower(attr.name)
    auth_attrs := {"authentication", "auth", "auth_enabled", "require_auth", "enable_authentication"}

    attr_name_lower == auth_attrs[_]
    check_missing_auth(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication is disabled or not required, allowing unauthorized access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_name_lower := lower(attr.name)
    network_attrs := {"cidr", "source_ip", "ip_range", "allowed_hosts", "ingress_cidr", "source_address_prefix"}

    attr_name_lower == network_attrs[_]
    check_open_network_access(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network access is open to the world (0.0.0.0/0), allowing unauthorized access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)

    found_admin := {a | a := attrs[_]; lower(a.name) == ["admin", "administrator", "root"][_]}
    found_guest := {a | a := attrs[_]; lower(a.name) == ["guest", "default", "anonymous"][_]}

    count(found_admin) > 0
    count(found_guest) > 0

    admin_attr := found_admin[_]
    guest_attr := found_guest[_]

    admin_attr.value.ir_type == "Boolean"
    admin_attr.value.value == true
    guest_attr.value.ir_type == "Boolean"
    guest_attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": admin_attr,
        "path": parent.path,
        "description": "Improper Access Control - Excessive privileges assigned to default or guest accounts. (CWE-284)"
    }
}