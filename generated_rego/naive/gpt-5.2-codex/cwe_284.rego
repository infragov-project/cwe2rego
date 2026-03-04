package glitch

import data.glitch_lib

public_access_keywords := {
    "public",
    "anonymous",
    "unauthenticated",
    "guest",
    "everyone",
    "allusers",
    "all_users",
    "allauthenticatedusers",
    "all_authenticated_users",
    "world",
    "internet",
    "public_access",
    "publicaccess",
    "public-access",
    "public-read",
    "public_read"
}

principal_field_keywords := {
    "principal",
    "member",
    "members",
    "subject",
    "user",
    "users",
    "group",
    "groups",
    "identity",
    "identities",
    "role",
    "roles"
}

wildcard_principal_values := {
    "any",
    "all",
    "everyone",
    "allusers",
    "all_users",
    "allauthenticatedusers",
    "all_authenticated_users",
    "world"
}

overpriv_keywords := {
    "admin",
    "administrator",
    "owner",
    "root",
    "superuser",
    "fullaccess",
    "full_access",
    "fullcontrol",
    "full_control",
    "writeall",
    "write_all",
    "privileged",
    "all_permissions"
}

auth_field_keywords := {
    "auth",
    "authorization",
    "authentication",
    "requireauth",
    "require_auth",
    "requireauthentication",
    "require_authentication",
    "disableauth",
    "disable_auth",
    "no_auth",
    "auth_required",
    "authorization_mode",
    "authentication_mode",
    "auth_method",
    "auth_type"
}

allow_unauth_keywords := {
    "allowunauthenticated",
    "allow_unauthenticated",
    "allowanonymous",
    "allow_anonymous",
    "unauthenticated",
    "anonymous",
    "guest",
    "noauth",
    "no_auth"
}

noauth_value_keywords := {
    "false",
    "none",
    "disabled",
    "off",
    "no",
    "null",
    "0"
}

network_field_keywords := {
    "cidr",
    "cidr_block",
    "cidr_blocks",
    "source",
    "source_ip",
    "source_ips",
    "ingress",
    "egress",
    "ip_range",
    "remote_ip",
    "remote_ip_prefix",
    "remote_ip_prefixes",
    "network",
    "security_group",
    "bind",
    "bind_addr",
    "bind_address",
    "bind_host",
    "bind_ip",
    "listen",
    "listen_addr",
    "listen_address",
    "listen_host",
    "listen_ip",
    "vncserver_listen",
    "vnc_listen",
    "public_ingress",
    "public_ip",
    "public_ip_address"
}

open_network_weak_values := {
    "any",
    "all",
    "any_ip",
    "allow_all",
    "public_ingress",
    "cidr=all",
    "source=all",
    "internet",
    "anywhere",
    "anywhere_ipv4",
    "anywhere_ipv6",
    "all_traffic",
    "open"
}

public_boundary_keywords := {
    "public_subnet",
    "external",
    "internet_facing",
    "exposed",
    "open_endpoint",
    "public_zone",
    "public_network",
    "public_net",
    "dmz"
}

action_resource_field_keywords := {
    "action",
    "actions",
    "resource",
    "resources",
    "permission",
    "permissions",
    "operation",
    "operations",
    "policy",
    "policies"
}

broad_scope_values := {
    "all",
    "any",
    "all_actions",
    "all_resources",
    "all_permissions",
    "fullaccess",
    "full_access",
    "fullcontrol",
    "full_control"
}

strong_open_values := {
    "0.0.0.0",
    "0.0.0.0/0",
    "::/0",
    "0/0"
}

kv_items(parent) = items {
    attrs := glitch_lib.all_attributes(parent)
    vars := glitch_lib.all_variables(parent)
    kvs := attrs | vars
    kvset := {{"key": kv.name, "value": kv.value, "element": kv} | kv := kvs[_]}
    hashset := {{"key": e.key.value, "value": e.value, "element": e.value} |
        walk(parent, [_, e])
        e.key
        e.value
        e.key.ir_type == "String"
    }
    items := kvset | hashset
}

key_has(item, keywords) {
    kw := keywords[_]
    glitch_lib.contains(item.key, kw)
}

value_has_keyword(value, keywords) {
    glitch_lib.traverse(value, keywords)
}

value_has_literal(value, lit) {
    walk(value, [_, node])
    node.ir_type == "String"
    node.value == lit
}
value_has_literal(value, lit) {
    walk(value, [_, node])
    node.ir_type == "VariableReference"
    node.value == lit
}

value_has_any_literal(value, lits) {
    lit := lits[_]
    value_has_literal(value, lit)
}

value_has_bool(value, b) {
    walk(value, [_, node])
    node.ir_type == "Boolean"
    node.value == b
}

value_is_false(value) {
    value_has_bool(value, false)
}
value_is_false(value) {
    value_has_literal(value, "false")
}
value_is_false(value) {
    value_has_literal(value, "0")
}

value_is_true(value) {
    value_has_bool(value, true)
}
value_is_true(value) {
    value_has_literal(value, "true")
}
value_is_true(value) {
    value_has_literal(value, "1")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, public_access_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Public or anonymous access enabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    value_has_keyword(item.value, public_access_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Public or anonymous access enabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, principal_field_keywords)
    value_has_keyword(item.value, wildcard_principal_values)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard principal or open policy. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, principal_field_keywords)
    value_has_literal(item.value, "*")
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard principal or open policy. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, overpriv_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Over-permissive roles or privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    value_has_keyword(item.value, overpriv_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Over-permissive roles or privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, auth_field_keywords)
    value_is_false(item.value)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Authentication or authorization disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, auth_field_keywords)
    value_has_keyword(item.value, noauth_value_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Authentication or authorization disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, allow_unauth_keywords)
    value_is_true(item.value)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Authentication or authorization disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, network_field_keywords)
    value_has_any_literal(item.value, strong_open_values)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Open network exposure to all IPs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, network_field_keywords)
    value_has_keyword(item.value, open_network_weak_values)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Open network exposure to all IPs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, network_field_keywords)
    value_has_literal(item.value, "*")
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Open network exposure to all IPs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    v := strong_open_values[_]
    node.value == v
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Open network exposure to all IPs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "VariableReference"
    v := strong_open_values[_]
    node.value == v
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Open network exposure to all IPs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, public_boundary_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Improper trust boundary or public placement. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    value_has_keyword(item.value, public_boundary_keywords)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Improper trust boundary or public placement. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, action_resource_field_keywords)
    value_has_keyword(item.value, broad_scope_values)
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Broad action or resource scope. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, action_resource_field_keywords)
    value_has_literal(item.value, "*")
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Broad action or resource scope. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    items := kv_items(parent)
    item := items[_]
    key_has(item, {"effect"})
    value_has_keyword(item.value, {"allow"})
    result := {
        "type": "sec_invalid_bind",
        "element": item.element,
        "path": parent.path,
        "description": "Improper Access Control - Broad action or resource scope. (CWE-284)"
    }
}