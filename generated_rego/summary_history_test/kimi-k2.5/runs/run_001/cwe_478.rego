package glitch

import data.glitch_lib

is_if_type(node) {
	node.type == "IF"
}

is_switch_type(node) {
	node.type == "SWITCH"
}

is_conditional_type(node) {
	is_if_type(node)
}

is_conditional_type(node) {
	is_switch_type(node)
}

get_else_chain(node) = chain {
	node.ir_type == "ConditionalStatement"
	elses := {e |
		walk(node, [_, e])
		e.ir_type == "ConditionalStatement"
		e != node
	}
	chain := {node} | elses
}

has_unconditional_else(n) {
	n.ir_type == "ConditionalStatement"
	n.else_statement != null
	s := n.else_statement
	s.ir_type == "ConditionalStatement"
	s.is_default == true
}

has_unconditional_else(n) {
	n.ir_type == "ConditionalStatement"
	n.else_statement != null
	s := n.else_statement
	s.ir_type == "ConditionalStatement"
	s.condition == null
}

has_unconditional_else(n) {
	n.ir_type == "ConditionalStatement"
	n.else_statement != null
	s := n.else_statement
	s.ir_type == "ConditionalStatement"
	s.condition.ir_type == "Null"
}

has_unconditional_else(n) {
	n.ir_type == "ConditionalStatement"
	n.is_default == true
}

chain_has_fallback(start_node) {
	chain := get_else_chain(start_node)
	some m in chain
	has_unconditional_else(m)
}

is_lookup_function(name) {
	lower_name := lower(name)
	contains(lower_name, "lookup")
}

is_lookup_function(name) {
	lower_name := lower(name)
	contains(lower_name, "map")
}

is_lookup_function(name) {
	lower_name := lower(name)
	contains(lower_name, "switch")
}

lookup_has_default(args, attrs) {
	some arg in args
	arg.ir_type == "String"
	contains(lower(arg.value), "default")
}

lookup_has_default(args, attrs) {
	some attr in attrs
	attr.name == "default"
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	conds := {n |
		walk(parent, [_, n])
		n.ir_type == "ConditionalStatement"
		n.is_top == true
	}

	node := conds[_]

	is_conditional_type(node)

	not chain_has_fallback(node)

	result := {
		"type": "sec_no_default_switch",
		"element": node,
		"path": parent.path,
		"description": "Missing default case in conditional - Conditional statements must have an exhaustive default/fallback branch. (CWE-478)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	au := {n |
		walk(parent, [_, n])
		n.ir_type == "AtomicUnit"
	}[_]

	n := au
	n.name.ir_type == "String"
	is_lookup_function(n.name.value)
	not lookup_has_default(n.args, n.attributes)

	result := {
		"type": "sec_no_default_switch",
		"element": n,
		"path": parent.path,
		"description": "Incomplete lookup/mapping without default - Lookups and mappings should include a default value for unhandled keys. (CWE-478)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""

	attrs := {n |
		walk(parent, [_, n])
		n.ir_type == "Attribute"
	}[_]

	n := attrs.value
	n.ir_type == "Hash"

	walk(n, [_, v])
	v.ir_type == "FunctionCall"
	is_lookup_function(v.name)

	not lookup_has_default(v.args, [])

	result := {
		"type": "sec_no_default_switch",
		"element": attrs,
		"path": parent.path,
		"description": "Incomplete lookup/mapping without default - Lookups and mappings should include a default value for unhandled keys. (CWE-478)"
	}
}