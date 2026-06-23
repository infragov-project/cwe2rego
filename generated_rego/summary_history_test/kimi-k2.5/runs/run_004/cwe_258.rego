package glitch

import data.glitch_lib
import future.keywords.if
import future.keywords.in

password_keywords := {"password", "passwd", "pwd", "secret", "secret_key", "client_secret", "credentials", "creds", "auth_token", "access_token", "token", "api_key", "apikey", "api_secret", "private_key", "passphrase", "admin_password", "root_password", "master_password", "cluster_password", "db_password", "database_password", "replication_password", "activationkey", "ssh_password", "activation_key", "ssh_key"}

is_empty_value(value) if {
	value.ir_type == "String"
	value.value == ""
}

is_empty_value(value) if {
	value.ir_type == "Null"
}

is_empty_value(value) if {
	value.ir_type == "Undef"
}

contains_keyword(name) if {
	lower_name := lower(name)
	some kw in password_keywords
	regex.match(sprintf(".*\\b%s\\b.*", [kw]), lower_name)
} else {
	lower_name := lower(name)
	some kw in password_keywords
	contains(lower_name, kw)
}

collect_all_vars_recursive(node) = vars if {
	vars := {v |
		walk(node, [_, x])
		x.ir_type == "Variable"
		v := x
	}
}

collect_all_attrs_recursive(node) = attrs if {
	attrs := {a |
		walk(node, [_, x])
		x.ir_type == "Attribute"
		a := x
	}
}

Glitch_Analysis[result] if {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	some var in parent.variables
	contains_keyword(var.name)
	is_empty_value(var.value)
	
	result := {"type": "sec_empty_pass", "element": var, "path": parent.path, "description": "Empty password in configuration file - Credentials should not be empty strings, null, or undefined. (CWE-258)"}
}

Glitch_Analysis[result] if {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	some var in collect_all_vars_recursive(parent)
	contains_keyword(var.name)
	is_empty_value(var.value)
	
	result := {"type": "sec_empty_pass", "element": var, "path": parent.path, "description": "Empty password in configuration file - Credentials should not be empty strings, null, or undefined. (CWE-258)"}
}

Glitch_Analysis[result] if {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	some attr in collect_all_attrs_recursive(parent)
	contains_keyword(attr.name)
	is_empty_value(attr.value)
	
	result := {"type": "sec_empty_pass", "element": attr, "path": parent.path, "description": "Empty password in configuration file - Credentials should not be empty strings, null, or undefined. (CWE-258)"}
}