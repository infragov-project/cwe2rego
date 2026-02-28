package glitch

import data.glitch_lib

open_cidr_values := {"0.0.0.0/0", "::/0"}
open_network_values := {"0.0.0.0/0", "::/0", "0.0.0.0"}
network_source_attr_names := {"cidr", "cidr_block", "cidr_ip", "source", "source_ranges", "src", "from_ip", "remote_ip", "remote_ip_prefix", "source_address"}
public_block_names := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
auth_flag_names := {"authentication_enabled", "require_auth", "api_key_required"}
public_ip_names := {"assign_public_ip", "associate_public_ip_address"}
logging_flag_names := {"enable_logging", "cloudtrail_enabled", "flow_logs_enabled"}
wildcard_action_names := {"action", "actions", "verbs", "apiGroups"}
principal_names := {"principal", "members", "subjects"}

is_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
}

is_wildcard(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_all_protocols(value) {
    value.ir_type == "String"
    value.value == "-1"
}

is_all_protocols(value) {
    value.ir_type == "Integer"
    value.value == -1
}

is_all_protocols(value) {
    value.ir_type == "String"
    regex.match("(?i)^all$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_action_names[_]
    is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard action/verb permission grant detected - Using '*' allows all actions without restriction. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"resource", "resources"}[_]
    is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard resource field detected - Using '*' grants access to all resources. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "permissions"
    is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permissions detected - Using '*' grants unrestricted access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == principal_names[_]
    is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted principal access - Wildcard principal allows any identity to access this resource. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "members"
    attr.value.ir_type == "String"
    attr.value.value == {"allUsers", "allAuthenticatedUsers"}[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "GCP IAM binding grants access to allUsers or allAuthenticatedUsers. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "subjects"
    attr.value.ir_type == "String"
    regex.match("(?i)system:(anonymous|unauthenticated)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "RBAC binding grants permissions to anonymous or unauthenticated Kubernetes subjects. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"anonymous_access", "anonymous_auth_enabled"}[_]
    is_enabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Anonymous access is enabled - Disable anonymous access to prevent unauthenticated resource access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    attr.value.value == {"public-read", "public-read-write"}[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public storage ACL detected - Storage resource is configured with public read or read-write access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == public_block_names[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public storage block setting is disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "public_access"
    attr.value.ir_type == "String"
    regex.match("(?i)^enabled$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access is explicitly enabled for a resource. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "public_access_prevention"
    attr.value.ir_type == "String"
    regex.match("(?i)^inherited$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access prevention is set to 'inherited' - Set to 'enforced'. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == network_source_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == open_cidr_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network CIDR detected - Allows traffic from any IP address. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "source_ranges"
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    elem.value == open_cidr_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted source_ranges - Firewall rule allows traffic from any IP address. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"protocol", "proto"}[_]
    is_all_protocols(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "All network protocols are permitted in a firewall rule. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i)(listen|bind_addr|bind_address|bind_ip)", entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value == open_network_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Service is bound or listening on all network interfaces (0.0.0.0) - Restrict binding to specific interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == network_source_attr_names[_]
    entry.value.ir_type == "String"
    entry.value.value == open_cidr_values[_]
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Unrestricted network CIDR in configuration hash - Allows traffic from any IP address. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"authorization_type", "auth_type"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^none$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authorization type is set to NONE - All services must enforce authentication. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == auth_flag_names[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication requirement is disabled - Enable authentication controls. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "unauthenticated_access"
    attr.value.ir_type == "String"
    regex.match("(?i)^allow$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unauthenticated access is explicitly permitted. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "publicly_accessible"
    is_enabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource is publicly accessible - Restrict access to prevent direct internet exposure. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == public_ip_names[_]
    is_enabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public IP address is assigned to resource. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "scheme"
    attr.value.ir_type == "String"
    attr.value.value == "internet-facing"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource scheme is internet-facing - Use internal scheme where public access is not required. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "internet_facing"
    is_enabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource is flagged as internet-facing. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "role_ref"
    attr.value.ir_type == "String"
    regex.match("(?i)^cluster-admin$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Cluster-admin role binding detected - Grants unrestricted Kubernetes administrative access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "default_action"
    attr.value.ir_type == "String"
    regex.match("(?i)^allow$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Default ACL/WAF action is ALLOW - Default policy should be DENY. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "trusted_entity"
    is_wildcard(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard trust entity - Restrict trust relationships to specific identities. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == logging_flag_names[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Access logging is disabled - Enable logging for audit trails and security monitoring. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "logging"
    attr.value.ir_type == "String"
    regex.match("(?i)^disabled$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Access logging is set to disabled - Enable access logging for audit trails. (CWE-284)"
    }
}