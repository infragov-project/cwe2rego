package glitch

import data.glitch_lib

high_privilege_principals := {"root", "administrator", "system", "admin"}

is_high_privilege_principal_string(str) {
    lower(str) == lower(high_privilege_principals[_])
}

# Check for principal in any String node via walk
has_high_privilege_in_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    is_high_privilege_principal_string(node.value)
}

# Also check for principal as substring with common delimiters (for cases like root@, root/, etc.)
has_high_privilege_in_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    str := node.value
    regex.match("(^|[^a-zA-Z0-9])root([^a-zA-Z0-9]|$)", str)
}

has_high_privilege_in_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    str := node.value
    regex.match("(^|[^a-zA-Z0-9])administrator([^a-zA-Z0-9]|$)", str)
}

has_high_privilege_in_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    str := node.value
    regex.match("(^|[^a-zA-Z0-9])system([^a-zA-Z0-9]|$)", str)
}

has_high_privilege_in_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    str := node.value
    regex.match("(^|[^a-zA-Z0-9])admin([^a-zA-Z0-9]|$)", str)
}

is_privileged_flag(value) {
    value.ir_type == "Boolean"
    value.value == true
} else {
    value.ir_type == "String"
    regex.match("(?i)^(privileged|true|yes|1)$", value.value)
}

is_user_attribute(name) {
    regex.match("(?i)^(remote_user|become_user|user|run_as|runAs|runuser|login|username)$", name)
}

has_wildcard_walk(value) {
    [_, node] := walk(value)
    node.ir_type == "String"
    node.value == "*"
}

# Check attributes on UnitBlock itself
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := parent.attributes[_]
    is_user_attribute(attr.name)
    has_high_privilege_in_walk(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Execution configured to run as high-privilege principal. (CWE-250)"
    }
}

# Check attributes in AtomicUnits
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_user_attribute(attr.name)
    has_high_privilege_in_walk(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Execution configured to run as high-privilege principal. (CWE-250)"
    }
}

# Detect high privilege principals in any string-valued attribute (command, script, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type != "Undef"
    has_high_privilege_in_walk(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - High-privilege principal embedded in command or configuration. (CWE-250)"
    }
}

# Detect privileged flags
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    regex.match("(?i)^privileged$", attr.name)
    is_privileged_flag(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged execution flag enabled without necessity. (CWE-250)"
    }
}

# Detect host namespace sharing
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    regex.match("(?i)^host_(network|pid|ipc)$", attr.name)
    is_privileged_flag(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Host namespace sharing enabled, granting excessive privileges. (CWE-250)"
    }
}

# Detect wildcard permissions in policy/permission attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    regex.match("(?i)(permission|action|resource|scope|capability|role|policy)", attr.name)
    has_wildcard_walk(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Overly permissive wildcard permissions detected in access configuration. (CWE-250)"
    }
}

# Detect SSH commands with high privilege principals
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check command-like attributes
    regex.match("(?i)^(command|cmd|script|exec|execute|shell)$", attr.name)
    has_high_privilege_in_walk(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - SSH or remote execution using high-privilege principal. (CWE-250)"
    }
}