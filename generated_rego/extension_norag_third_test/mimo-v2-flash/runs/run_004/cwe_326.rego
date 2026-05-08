package glitch

import data.glitch_lib

# Define weak encryption patterns
weak_algorithms := {"des", "3des", "rc4", "arc4", "blowfish", "idea", "ecb", "md5", "sha1", "sha-1", "md5_crypt"}
weak_key_sizes := {"64", "56", "128", "1024"}

# Check if a string contains a weak algorithm
is_weak_algorithm(val) {
	val.ir_type == "String"
	lower_val := lower(val.value)
	algorithm := weak_algorithms[_]
	contains(lower_val, algorithm)
}

# Check if a value represents a weak key size
is_weak_key_size(val) {
	val.ir_type == "Integer"
	val.value < 256
}

is_weak_key_size(val) {
	val.ir_type == "String"
	size := to_number(val.value)
	size < 256
}

# Detect weak encryption algorithm in attributes or variables
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	# Check attributes within the parent block
	attrs := glitch_lib.all_attributes(parent)
	attr := attrs[_]
	
	# Check if the attribute value or its nested elements contain weak algorithms
	walk(attr.value, [path, node])
	node.ir_type == "String"
	is_weak_algorithm(node)
	
	result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
		"description": "Inadequate Encryption Strength - Use of weak encryption algorithm. (CWE-326)"
	}
}

# Detect weak encryption algorithm in variables
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	vars := glitch_lib.all_variables(parent)
	var := vars[_]
	
	# Check if the variable value or its nested elements contain weak algorithms
	walk(var.value, [path, node])
	node.ir_type == "String"
	is_weak_algorithm(node)
	
	result := {
		"type": "sec_weak_crypt",
		"element": var,
		"path": parent.path,
		"description": "Inadequate Encryption Strength - Use of weak encryption algorithm. (CWE-326)"
	}
}

# Detect weak key size in attributes
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	attrs := glitch_lib.all_attributes(parent)
	attr := attrs[_]
	
	# Check if the attribute name suggests a key size and the value is weak
	regex.match("(?i).*(key|bits|size).*", attr.name)
	is_weak_key_size(attr.value)
	
	result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
		"description": "Inadequate Encryption Strength - Use of weak key size. (CWE-326)"
	}
}

# Detect weak key size in variables
Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	vars := glitch_lib.all_variables(parent)
	var := vars[_]
	
	# Check if the variable name suggests a key size and the value is weak
	regex.match("(?i).*(key|bits|size).*", var.name)
	is_weak_key_size(var.value)
	
	result := {
		"type": "sec_weak_crypt",
		"element": var,
		"path": parent.path,
		"description": "Inadequate Encryption Strength - Use of weak key size. (CWE-326)"
	}
}