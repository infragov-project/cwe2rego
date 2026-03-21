package glitch

import data.glitch_lib

auth_names := {"auth", "authentication", "authorization", "noauth", "unauthenticated", "anonymous", "allowunauthenticated", "publicaccess"}
public_names := {"public", "anonymous", "guest", "unauthenticated", "openaccess", "share", "publicread", "publicwrite", "worldreadable", "worldwritable", "publicaccess"}
policy_field_names := {"principal", "member", "subject", "action", "resource", "policy", "acl", "permission", "permissions", "role", "effect", "trust", "assumerole", "federated", "external"}
privilege_name_keywords := {"role", "permission", "permissions", "privilege", "privileged", "capability", "capabilities", "runas", "run_as", "sudo", "rights", "accesslevel", "access_level"}
perm_names := {"mode", "permission", "permissions", "chmod", "filemode"}
network_substrings := {"ingress", "egress", "cidr", "source", "sourcerange", "source_range", "portrange", "port_range", "port", "protocol", "bind", "bindip", "bind_ip", "bindaddress", "bind_address", "listen", "listenaddress", "listen_address", "address", "addr", "interface", "interfaces", "network"}

auth_disabled_regex := {"(?i)^false$", "(?i)^disabled$", "(?i)^none$", "(?i)^noauth$", "(?i)^unauthenticated$", "(?i)^anonymous$", "(?i)^off$"}
public_values_regex := {"(?i).*public.*", "(?i).*anonymous.*", "(?i).*unauthenticated.*", "(?i).*guest.*", "(?i).*worldreadable.*", "(?i).*worldwritable.*", "(?i).*openaccess.*", "(?i).*public[-_]?read.*", "(?i).*public[-_]?write.*", "(?i)^true$"}
wildcard_values_regex := {"(?i)^\\*$", "(?i).*\\*.*", "(?i)^any$", "(?i)^all$", "(?i)^everyone$", "(?i)^allusers$", "(?i)^anyone$", "(?i)^allowall$", "(?i)^allow_all$"}
privileged_values_regex := {"(?i).*admin.*", "(?i).*owner.*", "(?i).*root.*", "(?i).*superuser.*", "(?i).*fullcontrol.*", "(?i).*fullaccess.*", "(?i).*privileged.*", "(?i).*allpermissions.*"}
world_perm_regex := {"(?i)^0?777$", "(?i)^0?666$", "(?i)^rwxrwxrwx$", "(?i)^rw-rw-rw$"}
network_open_regex := {"(?i)(^|[^0-9])0\\.0\\.0\\.0([^0-9]|$)", "(?i)::/0", "(?i)^\\*$", "(?i)^any$", "(?i)^all$", "(?i)^0-65535$"}

contains_any(str, keywords) {
    kw := keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), str)
}

value_matches_any_regex(val, patterns) {
    pattern := patterns[_]
    glitch_lib.traverse(val, pattern)
}

value_has_int(val, nums) {
    num := nums[_]
    walk(val, [_, n])
    n.ir_type == "Integer"
    n.value == num
}

has_boolean_value(val, b) {
    walk(val, [_, n])
    n.ir_type == "Boolean"
    n.value == b
}

auth_disabled_value(v) {
    has_boolean_value(v, false)
} else {
    value_matches_any_regex(v, auth_disabled_regex)
}

public_access_value(v) {
    has_boolean_value(v, true)
} else {
    value_matches_any_regex(v, public_values_regex)
}

world_permission_value(v) {
    value_matches_any_regex(v, world_perm_regex)
} else {
    value_has_int(v, {777, 666})
}

all_keyvalues(node) = kvs {
    attrs := glitch_lib.all_attributes(node)
    vars := glitch_lib.all_variables(node)
    kvs = attrs | vars
}

network_key_name(name) {
    contains_any(name, network_substrings)
}

network_key_name(name) {
    regex.match("(?i)(^|[^a-z0-9])ip([^a-z0-9]|$)", name)
}

network_key_name(name) {
    regex.match("(?i)(^|[^a-z0-9])net([^a-z0-9]|$)", name)
}

network_key_name(name) {
    regex.match("(?i)(^|[^a-z0-9])host([^a-z0-9]|$)", name)
}

network_key_name(name) {
    regex.match("(?i)(^|[^a-z0-9])hostname([^a-z0-9]|$)", name)
}

expr_network_key(expr) {
    walk(expr, [_, n])
    n.ir_type == "String"
    network_key_name(n.value)
}

expr_network_key(expr) {
    walk(expr, [_, n])
    n.ir_type == "VariableReference"
    network_key_name(n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    contains_any(kv.name, auth_names)
    auth_disabled_value(kv.value)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Access control appears disabled or unauthenticated access is allowed. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    contains_any(kv.name, public_names)
    public_access_value(kv.value)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Resource configured for public or anonymous access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    contains_any(kv.name, policy_field_names)
    value_matches_any_regex(kv.value, wildcard_values_regex)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Overly permissive policy or wildcard access control detected. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    contains_any(kv.name, privilege_name_keywords)
    value_matches_any_regex(kv.value, privileged_values_regex)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Privileged role or full control permissions granted. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    contains_any(kv.name, perm_names)
    world_permission_value(kv.value)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "World-accessible file permissions detected. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]

    network_key_name(kv.name)
    value_matches_any_regex(kv.value, network_open_regex)

    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Unrestricted network access rule detected. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    kv := h.value[_]

    expr_network_key(kv.key)
    value_matches_any_regex(kv.value, network_open_regex)

    result := {
        "type": "sec_invalid_bind",
        "element": kv.value,
        "path": parent.path,
        "description": "Unrestricted network access rule detected. (CWE-284)"
    }
}