package glitch

import data.glitch_lib

authentication_keywords := {
	"password", "pass", "pwd", "secret", "token", "api_key", "key", "credential",
	"private_key", "certificate", "ssh_key", "keystore", "truststore",
	"keystore_password", "truststore_password", "sha512_password"
}

# Check if a string value represents a hardcoded credential (not empty)
is_hardcoded_credential(value) {
	value.ir_type == "String"
	value.value != ""
}

# Check if a key name is related to authentication/sensitive data
is_sensitive_key(key_name) {
	lower_key := lower(key_name)
	authentication_keywords[_] == lower_key
}

# Rule 1: Detect hardcoded credentials in top-level Variables (e.g., Chef attributes, Ansible vars)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	variables := glitch_lib.all_variables(parent)
	var := variables[_]
	is_sensitive_key(var.name)
	is_hardcoded_credential(var.value)
	result := {
		"type": "sec_hard_pass",
		"element": var,
		"path": parent.path,
		"description": sprintf("Use of Hard-coded Password - Variable '%s' contains a hardcoded credential. (CWE-259)", [var.name])
	}
}

# Rule 2: Detect hardcoded credentials in Atomic Units (e.g., Ansible tasks, Puppet resources, Chef resources)
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]
	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]
	is_sensitive_key(attr.name)
	is_hardcoded_credential(attr.value)
	result := {
		"type": "sec_hard_pass",
		"element": attr,
		"path": parent.path,
		"description": sprintf("Use of Hard-coded Password - Attribute '%s' contains a hardcoded credential. (CWE-259)", [attr.name])
	}
}

# Rule 3: Detect hardcoded credentials in Hash values nested within Variables or Attributes
# This handles cases like Ansible dictionaries where password is a key-value pair inside a hash
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Walk through all nodes in the parent to find Hash values
	walk(parent, [path, node])
	node.ir_type == "Hash"
	
	# Check each key-value pair in the Hash
	hash_pair := node.value[_]
	key_expr := hash_pair.key
	value_expr := hash_pair.value
	
	# Ensure the key is a String and is a sensitive key
	key_expr.ir_type == "String"
	is_sensitive_key(key_expr.value)
	
	# Ensure the value is a hardcoded credential
	is_hardcoded_credential(value_expr)
	
	result := {
		"type": "sec_hard_pass",
		"element": value_expr,
		"path": parent.path,
		"line": value_expr.line,
		"description": sprintf("Use of Hard-coded Password - Hash key '%s' contains a hardcoded credential. (CWE-259)", [key_expr.value])
	}
}

# Rule 4: Detect hardcoded credentials in Hash values nested within Arrays
# This handles cases like Ansible lists of dictionaries containing passwords
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Walk through all nodes in the parent to find Array values
	walk(parent, [path, node])
	node.ir_type == "Array"
	
	# Check each element in the Array
	array_element := node.value[_]
	
	# If the element is a Hash, check its key-value pairs
	array_element.ir_type == "Hash"
	hash_pair := array_element.value[_]
	key_expr := hash_pair.key
	value_expr := hash_pair.value
	
	# Ensure the key is a String and is a sensitive key
	key_expr.ir_type == "String"
	is_sensitive_key(key_expr.value)
	
	# Ensure the value is a hardcoded credential
	is_hardcoded_credential(value_expr)
	
	result := {
		"type": "sec_hard_pass",
		"element": value_expr,
		"path": parent.path,
		"line": value_expr.line,
		"description": sprintf("Use of Hard-coded Password - Hash key '%s' in Array contains a hardcoded credential. (CWE-259)", [key_expr.value])
	}
}

# Rule 5: Detect hardcoded credentials in Environment Variable Strings (e.g., Puppet env array)
# This handles cases where environment variables are defined as strings like "MYSQL_PASSWORD=some_password"
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Walk through all nodes to find Array values
	walk(parent, [path, node])
	node.ir_type == "Array"
	
	# Check each element in the Array
	array_element := node.value[_]
	
	# Check if the element is a String containing a key-value pair
	array_element.ir_type == "String"
	env_string := array_element.value
	
	# Check if the string matches a pattern like "KEY=value" where KEY is a sensitive key
	# We use regex to extract the key part before the '='
	regex.match("^[A-Z_]+PASSWORD=", env_string)
	
	result := {
		"type": "sec_hard_pass",
		"element": array_element,
		"path": parent.path,
		"line": array_element.line,
		"description": "Use of Hard-coded Password - Environment variable string contains a hardcoded password. (CWE-259)"
	}
}