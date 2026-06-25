package glitch

import data.glitch_lib

open_addresses := {"0.0.0.0", "0.0.0.0/0", "::/0"}

contains_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
}
contains_wildcard(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == "*"
}

contains_open_addr(value) {
    value.ir_type == "String"
    value.value == open_addresses[_]
}
contains_open_addr(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == open_addresses[_]
}

contains_all_users(value) {
    value.ir_type == "String"
    open_members := {"allUsers", "allAuthenticatedUsers"}
    value.value == open_members[_]
}
contains_all_users(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    open_members := {"allUsers", "allAuthenticatedUsers"}
    item.value == open_members[_]
}

wildcard_policy_attrs := {"actions", "resources", "principal", "not_actions", "not_resources"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_policy_attrs[_]
    contains_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy - Wildcard (*) used in actions, resources, or principal. (CWE-284)"
    }
}

public_block_attrs := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == public_block_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access block settings disabled - Storage may be publicly accessible. (CWE-284)"
    }
}

public_resource_attrs := {"publicly_accessible", "anonymous_access", "anonymous_auth"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == public_resource_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource publicly accessible or anonymous access enabled. (CWE-284)"
    }
}

cidr_attrs := {"cidr", "cidr_blocks", "ipv6_cidr_blocks", "source_ranges"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cidr_attrs[_]
    contains_open_addr(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - CIDR allows all traffic. (CWE-284)"
    }
}

no_auth_attrs := {"authorization_type", "authentication_type", "authorization"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == no_auth_attrs[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == "NONE"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Missing authentication or authorization - NONE value configured. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "members"
    contains_all_users(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource accessible by all users - members includes allUsers or allAuthenticatedUsers. (CWE-284)"
    }
}

privileged_attrs := {"privileged", "run_as_root"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == privileged_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container or process running with elevated privileges. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    public_acls := {"public-read", "public-read-write"}
    attr.value.value == public_acls[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Storage resource has a public ACL allowing unauthenticated access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "allowed_origins"
    contains_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "CORS configuration allows all origins (*) - insecure API exposure. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "endpoint_type"
    attr.value.ir_type == "String"
    upper(attr.value.value) == "PUBLIC"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "API or service endpoint is publicly exposed. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match("(?i).*(bind|listen|addr|address|ip|host).*", v.name)
    v.value.ir_type == "String"
    v.value.value == open_addresses[_]
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Service bound to all interfaces (0.0.0.0) - unrestricted network access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(bind|listen|addr|address|ip|host).*", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == open_addresses[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service bound to all interfaces (0.0.0.0) - unrestricted network access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_val := entry.key.value
    regex.match("(?i).*(bind|listen|addr|address|ip|host).*", key_val)
    entry.value.ir_type == "String"
    entry.value.value == open_addresses[_]
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Service bound to all interfaces (0.0.0.0) - unrestricted network access in hash configuration. (CWE-284)"
    }
}