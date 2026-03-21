package glitch

import data.glitch_lib

auth_tokens := {"auth", "authentication", "authorization"}
principal_tokens := {"principal", "member", "user", "group", "role", "owner", "identity", "account", "subject", "acl", "policy", "permission"}
permission_tokens := {"mode", "perm", "permission", "chmod", "umask"}

addr_tokens := {"bind", "bindip", "bind_ip", "bind-address", "bind_address", "listen", "listen_address", "listen_addr", "address", "addr", "ip", "ip_address", "ipaddr"}
source_tokens := {"cidr", "subnet", "network", "netmask", "source", "ingress", "egress", "from", "allow", "allowed", "permit", "peer", "remote", "range"}
host_tokens := {"host", "hostname"}

auth_disabled_patterns := {"(?i)^none$", "(?i)^no$", "(?i)^false$", "(?i)^disabled$", "(?i)^off$", "(?i).*unauthenticated.*", "(?i).*anonymous.*", "(?i).*no[_-]?auth.*"}
principal_open_patterns := {"(?i)^\\*$", "(?i)^anyone$", "(?i)^everyone$", "(?i)^public$", "(?i)^all[_-]?users$", "(?i).*all[_-]?users.*", "(?i).*any[_-]?user.*", "(?i).*public.*"}
world_perm_patterns := {"(?i)^0?777$", "(?i)^0?666$", "(?i).*world[_-]?readable.*", "(?i).*world[_-]?writable.*", "(?i).*public[_-]?read.*", "(?i).*public[_-]?write.*"}

open_addr_patterns := {"\\b0\\.0\\.0\\.0\\b", "::/0"}
open_any_patterns := {"\\b0\\.0\\.0\\.0\\b", "::/0", "(?i)anywhere", "^\\*$"}

desc_auth := "Authentication or authorization appears disabled, which can lead to improper access control. (CWE-284)"
desc_principal := "Access control policy appears overly permissive or public. (CWE-284)"
desc_perm := "World-readable or world-writable permissions detected. (CWE-284)"
desc_network := "Unrestricted network exposure detected (open address or source). (CWE-284)"

path_has_key(path) {
    path[_] == "key"
}

name_has_token(name, tokens) {
    tok := tokens[_]
    regex.match(sprintf("(?i).*%s.*", [tok]), name)
}

value_string_match(node, patterns) {
    pat := patterns[_]
    walk(node, [path, n])
    n.ir_type == "String"
    not path_has_key(path)
    regex.match(pat, n.value)
}

value_boolean_match(node, val) {
    walk(node, [path, n])
    n.ir_type == "Boolean"
    not path_has_key(path)
    n.value == val
}
value_boolean_match(node, val) {
    walk(node, [path, n])
    n.ir_type == "VariableReference"
    not path_has_key(path)
    regex.match(sprintf("(?i)^:?(%v)$", [val]), n.value)
}

value_integer_match(node, num) {
    walk(node, [path, n])
    n.ir_type == "Integer"
    not path_has_key(path)
    n.value == num
}

auth_disabled(node) {
    value_boolean_match(node, false)
}
auth_disabled(node) {
    value_string_match(node, auth_disabled_patterns)
}

open_principal(node) {
    value_string_match(node, principal_open_patterns)
}

world_perm(node) {
    value_integer_match(node, 777)
}
world_perm(node) {
    value_integer_match(node, 666)
}
world_perm(node) {
    value_string_match(node, world_perm_patterns)
}

open_addr(node) {
    value_string_match(node, open_addr_patterns)
}

open_any(node) {
    value_string_match(node, open_any_patterns)
}

hash_kv(node, k, v) {
    walk(node, [_, h])
    h.ir_type == "Hash"
    pair := h.value[_]
    k = pair.key
    v = pair.value
}

key_match(k, tokens) {
    k.ir_type == "String"
    name_has_token(k.value, tokens)
}
key_match(k, tokens) {
    k.ir_type == "VariableReference"
    name_has_token(k.value, tokens)
}

addr_key(k) {
    key_match(k, addr_tokens)
}
addr_key(k) {
    key_match(k, host_tokens)
}

source_key(k) {
    key_match(k, source_tokens)
}

addr_name(name) {
    name_has_token(name, addr_tokens)
}
addr_name(name) {
    name_has_token(name, host_tokens)
}

source_name(name) {
    name_has_token(name, source_tokens)
}

auth_kv(node, v) {
    hash_kv(node, k, v)
    key_match(k, auth_tokens)
    auth_disabled(v)
}

principal_kv(node, v) {
    hash_kv(node, k, v)
    key_match(k, principal_tokens)
    open_principal(v)
}

perm_kv(node, v) {
    hash_kv(node, k, v)
    key_match(k, permission_tokens)
    world_perm(v)
}

addr_kv(node, v) {
    hash_kv(node, k, v)
    addr_key(k)
    open_addr(v)
}

source_kv(node, v) {
    hash_kv(node, k, v)
    source_key(k)
    open_any(v)
}

network_name_value(name, value) {
    addr_name(name)
    open_addr(value)
}
network_name_value(name, value) {
    source_name(name)
    open_any(value)
}

network_kv(node, v) {
    addr_kv(node, v)
}
network_kv(node, v) {
    source_kv(node, v)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    name_has_token(attr.name, auth_tokens)
    auth_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": desc_auth
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    name_has_token(v.name, auth_tokens)
    auth_disabled(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": desc_auth
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    auth_kv(attr.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_auth
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    auth_kv(v.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_auth
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    name_has_token(attr.name, principal_tokens)
    open_principal(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": desc_principal
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    name_has_token(v.name, principal_tokens)
    open_principal(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": desc_principal
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    principal_kv(attr.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_principal
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    principal_kv(v.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_principal
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    name_has_token(attr.name, permission_tokens)
    world_perm(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": desc_perm
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    name_has_token(v.name, permission_tokens)
    world_perm(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": desc_perm
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    perm_kv(attr.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_perm
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    perm_kv(v.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_perm
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    network_name_value(attr.name, attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": desc_network
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    network_name_value(v.name, v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": desc_network
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    network_kv(attr.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_network
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    network_kv(v.value, val)
    result := {
        "type": "sec_invalid_bind",
        "element": val,
        "path": parent.path,
        "description": desc_network
    }
}