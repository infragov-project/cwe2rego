package glitch

import data.glitch_lib

# Helper: Identify "0.0.0.0" value
is_unrestricted_address(node) {
	node.ir_type == "String"
	node.value == "0.0.0.0"
}

# Helper: Identify binding/listening context names
is_binding_name(name) {
	regex.match("(?i)(listen|bind|server|host|ip|address|endpoint|expose|remote)", name)
}

# Rule 1: Direct Attribute Assignment
# Detects: attribute => "0.0.0.0"
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	attrs := glitch_lib.all_attributes(parent)
	attr := attrs[_]

	is_binding_name(attr.name)
	is_unrestricted_address(attr.value)

	result := {
		"type": "sec_invalid_bind",
		"element": attr,
		"path": parent.path,
		"description": "Service bound to 0.0.0.0 - Binding a service to 0.0.0.0 allows unrestricted network access. (CWE-1327)",
	}
}

# Rule 2: Variable Hash/Array Composition
# Detects: $var = { :ip => "0.0.0.0" } or complex nested structures
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	vars := glitch_lib.all_variables(parent)
	var := vars[_]

	# Search within the variable's complex value
	walk(var.value, [path, node])
	is_unrestricted_address(node)

	# Verify context by checking if the variable name implies binding
	# Or if the path implies a binding context (e.g., key is "ip", "bind-address")
	check_context(path, var.name)

	result := {
		"type": "sec_invalid_bind",
		"element": var,
		"path": parent.path,
		"description": "Service bound to 0.0.0.0 - Binding a service to 0.0.0.0 allows unrestricted network access. (CWE-1327)",
	}
}

# Rule 3: Attribute Hash/Array Composition
# Detects: attributes inside AtomicUnits containing "0.0.0.0" (e.g., Ansible vars)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]

	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]

	# Search within the attribute's complex value
	walk(attr.value, [path, node_val])
	is_unrestricted_address(node_val)

	# Verify context
	check_context(path, attr.name)

	result := {
		"type": "sec_invalid_bind",
		"element": attr,
		"path": parent.path,
		"description": "Service bound to 0.0.0.0 - Binding a service to 0.0.0.0 allows unrestricted network access. (CWE-1327)",
	}
}

# Helper: Check context for nested values
# path is a list of keys/indexes traversed to reach the node
# name is the name of the parent variable/attribute
check_context(path, name) {
	# If parent name implies binding, accept
	is_binding_name(name)
} else {
	# Else check if any key in the path implies binding
	some p
	path[p].value != ""
	is_binding_name(path[p].value)
}