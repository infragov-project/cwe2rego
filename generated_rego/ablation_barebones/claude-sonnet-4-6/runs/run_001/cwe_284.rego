package glitch

import data.glitch_lib

public_access_attr_names := {
    "public_access", "publicly_accessible", "public", "is_public",
    "enable_public_access", "public_network_access_enabled",
    "allow_public_access", "open_access", "anonymous_access"
}

auth_required_attr_names := {
    "authentication_enabled", "auth_enabled", "require_auth",
    "require_authentication", "authorization_enabled",
    "access_control_enabled", "authentication_required",
    "require_authorization", "enable_authentication"
}

public_access_strings := {
    "public", "open", "everyone", "anonymous",
    "public-read", "public-read-write", "public_read", "public_write"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == public_access_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured with public access enabled, potentially exposing it to unauthorized actors. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == auth_required_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Authentication or authorization is explicitly disabled, allowing unauthorized access to resources. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == public_access_attr_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == public_access_strings[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured with public or anonymous access, potentially exposing it to unauthorized actors. (CWE-284)"
    }
}