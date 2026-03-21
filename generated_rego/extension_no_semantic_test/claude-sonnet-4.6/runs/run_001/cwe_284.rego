package glitch

import data.glitch_lib

value_is_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
}

value_is_wildcard(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"action", "actions", "resource", "resources", "principal", "principals", "not_action", "not_resource"}[_]
    value_is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Wildcard permission grants unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"cidr", "cidr_block", "cidr_blocks", "source_ranges", "source_address_prefix", "remote_ip_prefix"}[_]
    glitch_lib.traverse(attr.value, "^(?:0\\.0\\.0\\.0/0|::/0)$")
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network rule allows traffic from any source (0.0.0.0/0 or ::/0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "publicly_accessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured to be publicly accessible. (CWE-284)"
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
        "description": "Improper Access Control - Public ACL exposes resource to unauthorized access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"block_public_acls", "block_public_policy", "restrict_public_buckets", "ignore_public_acls"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Public access block is disabled, exposing storage to public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"authorization_type", "authorization", "auth_type"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "none"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication is not configured on the endpoint. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"require_auth", "authentication_enabled", "enable_key_based_auth", "api_key_required"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication requirement is explicitly disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Container or process runs with elevated (privileged) access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"logging_enabled", "enable_access_logs", "cloudtrail_enabled", "flow_logs_enabled"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Access logging is disabled, reducing accountability. (CWE-284)"
    }
}