package glitch

import data.glitch_lib

has_wildcard_value(value) {
    value.ir_type == "String"
    value.value == "*"
}

has_wildcard_value(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == "*"
}

is_network_bind_name(name) {
    regex.match("(?i)bind", name)
}

is_network_bind_name(name) {
    regex.match("(?i)(^|[_:\\[])ip(\\]|$)", name)
}

is_network_bind_name(name) {
    regex.match("(?i)addr", name)
}

is_open_bind_value(v) {
    v.ir_type == "String"
    v.value == "0.0.0.0"
}

is_open_bind_value(v) {
    v.ir_type == "String"
    v.value == "::"
}

hash_key_name(entry) = name {
    entry.key.ir_type == "VariableReference"
    name = entry.key.value
}

hash_key_name(entry) = name {
    entry.key.ir_type == "String"
    name = entry.key.value
}

iam_wildcard_names := {"actions", "resources", "principal", "principals", "resource", "action"}
cors_wildcard_names := {"allowed_origins", "cors_allowed_origins"}
public_enabled_attrs := {"public_access", "publicly_accessible", "allow_unauthenticated_identities", "anonymous_access", "privileged", "run_as_root", "allow_privilege_escalation", "host_pid", "host_ipc", "host_network"}
security_disabled_attrs := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets", "run_as_non_root", "require_ssl", "enforce_https", "authentication_enabled", "require_auth"}
public_acl_values := {"public-read", "public-read-write", "authenticated-read"}
auth_attr_names := {"authorization", "authorization_type", "auth_type"}
auth_disabled_values := {"none", "disabled"}
cidr_attr_names := {"cidr_blocks", "source_ranges", "ip_ranges", "allowed_ips", "permitted_ips"}
open_cidrs := {"0.0.0.0/0", "::/0"}
all_protocol_values := {"-1", "all"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == iam_wildcard_names[_]
    has_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard in IAM attribute grants excessive privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == cors_wildcard_names[_]
    has_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - CORS wildcard origin enables cross-origin attacks. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == public_enabled_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource publicly accessible or elevated privilege enabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == security_disabled_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Security control is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "acl"
    attr.value.ir_type == "String"
    lower(attr.value.value) == public_acl_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Storage ACL allows public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == auth_attr_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == auth_disabled_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == cidr_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == open_cidrs[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Overly permissive CIDR block. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == cidr_attr_names[_]
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    item.value == open_cidrs[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Overly permissive CIDR block in list. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "protocol"
    attr.value.ir_type == "String"
    lower(attr.value.value) == all_protocol_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network rule allows all protocols. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_network_bind_name(v.name)
    is_open_bind_value(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_network_bind_name(attr.name)
    is_open_bind_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    name := hash_key_name(entry)
    is_network_bind_name(name)
    is_open_bind_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all network interfaces in config hash. (CWE-284)"
    }
}