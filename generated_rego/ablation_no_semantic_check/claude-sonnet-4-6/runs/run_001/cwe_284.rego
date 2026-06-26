package glitch

import data.glitch_lib

wildcard_perm_attrs := {"action", "actions", "resource", "resources", "permissions", "principal", "principals", "trusted_entity"}

public_true_attrs := {"public_access", "publicly_accessible", "public_network_access_enabled", "anonymous_access", "cross_tenant_access"}

security_must_enable_attrs := {"logging_enabled", "enable_access_logging", "rbac_enabled", "require_https", "enable_auth", "api_key_required", "block_public_acls", "block_public_policy", "restrict_public_buckets", "ignore_public_acls"}

auth_none_attrs := {"authorization", "authentication_type", "auth_type"}

open_cidr_regex := "^(0\\.0\\.0\\.0/0|::/0)$"

public_acl_regex := "(?i)^public-(read|read-write|write)$"

wildcard_regex := "^\\*$"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == wildcard_perm_attrs[_]
    attr.value.ir_type == "String"
    regex.match(wildcard_regex, attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive wildcard in access policy - Actions, resources or principals should not use wildcards. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == wildcard_perm_attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match(wildcard_regex, elem.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive wildcard in access policy array - Actions, resources or principals should not use wildcards. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == public_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled on resource - Resources should not be publicly accessible without restriction. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "acl"
    attr.value.ir_type == "String"
    regex.match(public_acl_regex, attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public ACL configured on resource - Resources should not use public-read or public-write ACLs. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "visibility"
    attr.value.ir_type == "String"
    regex.match("(?i)^public$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource visibility set to public - Resources should not be publicly visible without restriction. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == auth_none_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^none$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication or authorization set to NONE - Resources must enforce authentication mechanisms. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "unauthenticated_identities"
    attr.value.ir_type == "String"
    regex.match("(?i)^allow$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unauthenticated identities are allowed - Anonymous access should not be permitted. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == security_must_enable_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Critical security or access control feature is disabled - Security features must be enabled to enforce proper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "cidr"
    attr.value.ir_type == "String"
    regex.match(open_cidr_regex, attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access via open CIDR - Firewall and network rules should not allow access from all sources. (CWE-284)"
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
    regex.match(open_cidr_regex, elem.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access via open source range - Network policies should not allow access from all sources. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == "endpoint_type"
    attr.value.ir_type == "String"
    regex.match("(?i)^public$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "API endpoint type set to PUBLIC - Endpoints should enforce access policy restrictions. (CWE-284)"
    }
}