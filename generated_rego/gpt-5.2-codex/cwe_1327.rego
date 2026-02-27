package glitch

import data.glitch_lib

bind_field(name) {
	lname := lower(name)
	regex.match(".*(bind|listen|host|address|addr|interface|socket|service|endpoint|ingress|public|advertise|source).*", lname)
}

bind_field(name) {
	lower(name) == "ip"
}

unrestricted_bind_value(value) {
	pattern := "(?i)^\\s*['\"]?(?:0\\.0\\.0\\.0(?:/0)?(?::\\d+)?|::0?(?::\\d+)?|\\*(?::\\d+)?|any(?:host)?|all_interfaces)['\"]?\\s*$"
	glitch_lib.traverse(value, pattern)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	attr := glitch_lib.all_attributes(parent)[_]
	bind_field(attr.name)
	unrestricted_bind_value(attr.value)

	result := {
		"type": "sec_invalid_bind",
		"element": attr,
		"path": parent.path,
		"description": "Binding to an unrestricted IP address - Services should not bind/listen on all interfaces (0.0.0.0, ::, *). (CWE-1327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	v := glitch_lib.all_variables(parent)[_]
	bind_field(v.name)
	unrestricted_bind_value(v.value)

	result := {
		"type": "sec_invalid_bind",
		"element": v,
		"path": parent.path,
		"description": "Binding to an unrestricted IP address - Services should not bind/listen on all interfaces (0.0.0.0, ::, *). (CWE-1327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	attr := glitch_lib.all_attributes(parent)[_]
	walk(attr.value, [_, node])
	keyobj := node.key
	valobj := node.value
	keyobj.ir_type == "String"
	bind_field(keyobj.value)
	unrestricted_bind_value(valobj)

	result := {
		"type": "sec_invalid_bind",
		"element": valobj,
		"path": parent.path,
		"description": "Binding to an unrestricted IP address - Services should not bind/listen on all interfaces (0.0.0.0, ::, *). (CWE-1327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	v := glitch_lib.all_variables(parent)[_]
	walk(v.value, [_, node])
	keyobj := node.key
	valobj := node.value
	keyobj.ir_type == "String"
	bind_field(keyobj.value)
	unrestricted_bind_value(valobj)

	result := {
		"type": "sec_invalid_bind",
		"element": valobj,
		"path": parent.path,
		"description": "Binding to an unrestricted IP address - Services should not bind/listen on all interfaces (0.0.0.0, ::, *). (CWE-1327)"
	}
}