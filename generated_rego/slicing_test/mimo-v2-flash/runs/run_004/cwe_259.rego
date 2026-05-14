package glitch

import data.glitch_lib

# Define sensitive keywords that indicate potential hard-coded passwords
sensitive_keywords := {"password", "passphrase", "secret", "token", "credential", "pwd", "key"}

# Check if a string value is a hard-coded password literal
is_hardcoded_password(val) {
	val.ir_type == "String"
	val.value != ""
	# Exclude common false positives
	not regex.match(`^\{\{.*\}\}$`, val.value)
	not regex.match(`^env\[.*\]$`, val.value)
	not regex.match(`^var\.`, val.value)
	not regex.match(`^/`, val.value)
	not regex.match(`^\.`, val.value)
	val.value != "true"
	val.value != "false"
}

# Helper to check if a key name indicates a sensitive value
is_sensitive_key(key) {
	lower_key := lower(key)
	some keyword
	sensitive_keywords[keyword]
	contains(lower_key, keyword)
}

# Main rule for detecting CWE-259 in Variables
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	
	node.ir_type == "Variable"
	is_sensitive_key(node.name)
	node.value.ir_type == "String"
	is_hardcoded_password(node.value)
	
	result := {
		"type": "sec_hard_pass",
		"element": node,
		"path": parent.path,
		"line": node.line,
		"description": "Use of hard-coded password - Avoid storing credentials directly in code. (CWE-259)"
	}
}

# Main rule for detecting CWE-259 in Attributes
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	
	node.ir_type == "Attribute"
	is_sensitive_key(node.name)
	node.value.ir_type == "String"
	is_hardcoded_password(node.value)
	
	result := {
		"type": "sec_hard_pass",
		"element": node,
		"path": parent.path,
		"line": node.line,
		"description": "Use of hard-coded password - Avoid storing credentials directly in code. (CWE-259)"
	}
}

# Rule for detecting passwords in Hash key-value pairs (nested or not)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	
	node.ir_type == "Hash"
	some k, v
	node.value[k].ir_type == "String"
	is_sensitive_key(node.value[k].value)
	node.value[k].ir_type == "String"
	is_hardcoded_password(node.value[k])
	
	result := {
		"type": "sec_hard_pass",
		"element": node.value[k],
		"path": parent.path,
		"line": node.value[k].line,
		"description": "Use of hard-coded password - Avoid storing credentials directly in code. (CWE-259)"
	}
}

# Rule for detecting passwords in Array elements (e.g., env vars in Puppet/Ansible)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	
	node.ir_type == "Array"
	some i
	node.value[i].ir_type == "String"
	
	# Check if the string contains a password pattern like "PASSWORD=..." or "password:..."
	regex.match(`(?i).*(password|secret|token|key|credential|pwd).*=\s*[^$&]*`, node.value[i].value)
	
	# Ensure it's a hard-coded value (not a variable reference)
	is_hardcoded_password(node.value[i])
	
	result := {
		"type": "sec_hard_pass",
		"element": node.value[i],
		"path": parent.path,
		"line": node.value[i].line,
		"description": "Use of hard-coded password - Avoid storing credentials directly in code. (CWE-259)"
	}
}