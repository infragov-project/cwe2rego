package glitch

import data.glitch_lib

suspicious_patterns := {
	"BUG", "BUGFIX", "KNOWN-ISSUE", "BROKEN", "WORKAROUND", "KLUDGE",
	"TODO", "FIXME", "XXX", "HACK", "TEMP", "TEMPORARY", "PLACEHOLDER", "STUB",
	"LATER", "FUTURE", "NEXT-RELEASE", "BACKLOG", "PENDING", "NOT-IMPLEMENTED",
	"REVIEW", "AUDIT", "QUESTION", "APPROVAL-NEEDED", "CLEANUP",
	"SECURITY-TODO", "AUTH-TODO", "ENCRYPT-LATER", "CERT-PLACEHOLDER", "HARDCODED-SECRET", "DISABLE-CHECK",
	"HARDCODED", "HARDCODE", "MANUAL-CONFIG", "OVERRIDE-ME", "CHANGE-ME"
}

has_suspicious_pattern(content) {
	pattern := suspicious_patterns[_]
	regex.match(sprintf("(?i)\\b%s\\b", [pattern]), content)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	
	comment := parent.comments[_]
	has_suspicious_pattern(comment.content)
	
	result := {
		"type": "sec_susp_comm",
		"element": comment,
		"path": parent.path,
		"description": "Suspicious Comment - Code contains comments that may indicate security gaps or incomplete functionality. (CWE-546)"
	}
}