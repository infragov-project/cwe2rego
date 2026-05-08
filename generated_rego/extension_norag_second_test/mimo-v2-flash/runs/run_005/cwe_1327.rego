package glitch

import data.glitch_lib

# Helper to check if a node's value is the string "0.0.0.0"
is_unrestricted_bind(node) {
	node.ir_type == "String"
	node.value == "0.0.0.0"
}

# Rule for Variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Look specifically for Variable definitions
	vars := glitch_lib.all_variables(parent)
	var_node := vars[_]
	
	# Check if the variable's value is 0.0.0.0
	is_unrestricted_bind(var_node.value)
	
	result := {
		"type": "sec_invalid_bind",
		"element": var_node,
		"path": parent.path,
		"description": "Service binding to 0.0.0.0 - Binding a service to all network interfaces increases attack surface. (CWE-1327)"
	}
}

# Rule for Attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Look specifically for Attribute definitions
	attrs := glitch_lib.all_attributes(parent)
	attr := attrs[_]
	
	# Check if the attribute value is 0.0.0.0
	is_unrestricted_bind(attr.value)
	
	result := {
		"type": "sec_invalid_bind",
		"element": attr,
		"path": parent.path,
		"description": "Service binding to 0.0.0.0 - Binding a service to all network interfaces increases attack surface. (CWE-1327)"
	}
}

# Rule for Complex Values (Hashes/Arrays)
# This captures cases like Chef's Hash or Ansible complex vars where 0.0.0.0 is a value inside a structure
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Walk the entire parent to find any node with value 0.0.0.0
	walk(parent, [path, node])
	is_unrestricted_bind(node)
	
	# Ensure we aren't re-reporting the same nodes found by the specific rules above
	# (Variables and Attributes are already covered, this catches nested complex values)
	not node.ir_type == "Variable"
	not node.ir_type == "Attribute"
	
	result := {
		"type": "sec_invalid_bind",
		"element": node,
		"path": parent.path,
		"description": "Service binding to 0.0.0.0 - Binding a service to all network interfaces increases attack surface. (CWE-1327)"
	}
}