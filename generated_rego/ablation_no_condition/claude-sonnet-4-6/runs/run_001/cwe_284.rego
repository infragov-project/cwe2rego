package glitch

import data.glitch_lib

is_open_bind_value(val) {
    val.ir_type == "String"
    regex.match(`^(\*|0\.0\.0\.0(/0)?|::/0)$`, val.value)
}

is_bind_related_name(name) {
    regex.match(`(?i)(bind|addr|listen|cidr|source_range|allow_from|net_bindip)`, name)
}

is_bind_related_name(name) {
    regex.match(`(?i)(^ip$|^ip[_:\-]|[_:\-]ip$|[_:\-]ip[_:\-])`, name)
}

get_entry_key_name(entry) = name {
    entry.key.ir_type == "String"
    name := entry.key.value
}

get_entry_key_name(entry) = name {
    entry.key.ir_type == "VariableReference"
    name := entry.key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(publicly.?accessible|is.?public|public.?access|allow.?public|enable.?public|allow.?unauthenticated|anonymous.?access)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource is configured with public access enabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_bind_related_name(attr.name)
    is_open_bind_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Resource allows unrestricted network access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := get_entry_key_name(entry)
    is_bind_related_name(key_name)
    is_open_bind_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains open bind address. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, v])
    v.ir_type == "Variable"
    is_bind_related_name(v.name)
    is_open_bind_value(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Improper Access Control - Service is configured to bind to all network interfaces. (CWE-284)"
    }
}