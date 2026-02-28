package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    binding_fields := {"listenaddr", "bind_address", "address", "host", "ip", "interface", "bind"}
    attr.name == binding_fields[_]
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"

    comment := parent.comments[_]
    scalar := comment.content
    any {
        regex.match("(?i)internal", scalar)
        regex.match("(?i)private", scalar)
        regex.match("(?i)internal-only", scalar)
    }

    severity := "high"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to unrestricted IP address 0.0.0.0 exposes the service to all network interfaces. This is a critical risk for internal services. (CWE-1327)",
        "severity": severity
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    risky_flags := {"bind_to_all_interfaces", "public_access", "allow_all", "expose", "external"}
    attr.name == risky_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    binding_attr := attrs[_]
    binding_fields := {"listenaddr", "bind_address", "address", "host", "ip", "interface", "bind"}
    binding_attr.name == binding_fields[_]
    binding_attr.value.ir_type == "String"
    binding_attr.value.value == "0.0.0.0"

    severity := "high"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service is configured for unrestricted access via flag (e.g., public_access=true or bind_to_all_interfaces=true), increasing exposure. (CWE-1327)",
        "severity": severity
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "host"
    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to wildcard host '*' implies unrestricted exposure to all interfaces. This is a sign of unrestricted binding. (CWE-1327)",
        "severity": "medium"
    }
}