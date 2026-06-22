package glitch

import data.glitch_lib
import future.keywords.in

privilege_indicators := {
	"privileged",
	"runAsRoot",
	"allowPrivilegeEscalation",
	"hostPID",
	"hostNetwork",
	"remote_user",
	"user"
}

root_indicators := {
	"runAsUser",
	"runAsGroup",
	"fsGroup"
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]

	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]

	privilege_indicators[attr.name]
	attr.value.ir_type == "String"
	attr.value.value == "root"

	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Running as 'root' user introduces security risks. Use a less privileged user whenever possible. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]

	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]

	privilege_indicators[attr.name]
	attr.value.ir_type == "Boolean"
	attr.value.value == true

	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Using elevated permissions such as 'privileged: true' unnecessarily increases the attack surface. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]

	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]

	root_indicators[attr.name]
	attr.value.ir_type == "Integer"
	attr.value.value == 0

	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Running processes as root (UID/GID=0) introduces risk if those privileges are not strictly required. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]

	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]
	attr.name == "capabilities"
	
	attr.value.ir_type == "Array"
	values := attr.value.value
	some v in values
	v.ir_type == "String"
	regex.match("(?i)all", v.value)

	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Granting 'ALL' capabilities can expose the system to privilege escalation risks. Consider minimizing required capabilities. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	all_attributes_set := glitch_lib.all_attributes(parent)
	attr := all_attributes_set[_]
	
	privilege_indicators[attr.name]
	attr.value.ir_type == "String"
	attr.value.value == "root"
	
	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Running as 'root' user introduces security risks. Use a less privileged user whenever possible. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]
	
	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]
	attr.name == "command"
	
	attr.value.ir_type == "String"
	regex.match(".*\\broot@.*", attr.value.value)
	
	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Command includes SSH connection as 'root' user which introduces security risks. Use a less privileged user whenever possible. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	atomic_units := glitch_lib.all_atomic_units(parent)
	node := atomic_units[_]
	
	attrs := glitch_lib.all_attributes(node)
	attr := attrs[_]
	attr.name == "command"
	
	attr.value.ir_type == "Sum"
	command_string := sprintf("%v", [attr.value])
	regex.match(".*\\broot@.*", command_string)
	
	result := {
		"type": "sec_def_admin",
		"element": attr,
		"path": parent.path,
		"description": "Execution with unnecessary privileges detected. Command includes SSH connection as 'root' user which introduces security risks. Use a less privileged user whenever possible. (CWE-250)"
	}
}