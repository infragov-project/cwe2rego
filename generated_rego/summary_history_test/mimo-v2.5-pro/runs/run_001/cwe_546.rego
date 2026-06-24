package glitch

import data.glitch_lib

# Combined suspicious patterns - carefully curated to minimize false positives
suspicious_patterns := [
    # Action-required markers indicating incomplete work
    `\b(?:TODO|FIXME|BUG|XXX|OPTIMIZE|REFACTOR)\b`,
    # Temporal/deprecated markers - explicit indicators of outdated or temporary code
    `\bDEPRECATED\b`,
    # Workaround and temporary fix indicators
    `\b(?:WORKAROUND|TEMP(?:ORARY)?\s+FIX)\b`,
    # Deferred action indicators
    `\b(?:NEEDS?\s+REVIEW|REVISIT|CLEANUP)\b`,
    # Security-specific concerns
    `\bHARDCODED?\s+(?:CREDENTIALS?|PASSWORDS?|SECRETS?|KEYS?|TOKENS?)\b`,
    `\b(?:INSECURE|DANGEROUS|RISKY)\b`,
    `\b(?:SKIP|DISABLE)\s+(?:TLS|SSL|VERIF(?:Y|ICATION))\b`,
    `\bDEFAULT\s+(?:ADMIN\s+)?(?:PASSWORD|CREDENTIALS?|KEY|TOKEN|SECRET)\b`,
    `\b(?:WEAK|VULNERABLE)\s+(?:PASSWORD|CREDENTIALS?|KEY|ENCRYPT(?:ION)?|CIPHER|HASH)\b`,
    `\b(?:SECURITY|AUTH(?:N|Z)?)\s+(?:BYPASS|DISABLED?|WEAK|MISSING)\b`,
    `\b(?:DO\s+NOT\s+DEPLOY|NOT\s+FOR\s+PRODUCTION|REMOVE\s+BEFORE|PLACEHOLDER)\b`,
    `\b(?:BROAD\s+ACCESS|0\.0\.0\.0/0)\b`,
    `\bOVERRID(?:E|ING)\s+(?:CIS|SECURITY)\b`,
    `\bNON[\-]?COMPLIANT\b`,
    # Issue tracker and vulnerability references
    `(?:issues|bugs|tickets)/\d+`,
    `CVE-\d{4}-\d+`,
    `GHSA-[\w]+-[\w]+-[\w]+`,
    # General known-issue indicators (cannot change, will break)
    `\b(?:CANNOT\s+CHANGE|WILL\s+BREAK|WILL\s+CAUSE)\b`,
    `\bHACK\b`,
]

is_suspicious(content) {
    pattern := suspicious_patterns[_]
    regex.match(sprintf("(?i)%s", [pattern]), content)
}

suspicion_desc(content) = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:TODO|FIXME|BUG|XXX|OPTIMIZE|REFACTOR)\b`]), content)
    desc := "Suspicious comment with action-required marker indicating incomplete implementation or known issue. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\bDEPRECATED\b`]), content)
    desc := "Suspicious comment indicating deprecated configuration or feature that may contain known vulnerabilities. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [sprintf("%s|%s", [`(?:issues|bugs|tickets)/\d+`, `CVE-\d{4}-\d+|GHSA-[\w]+-[\w]+-[\w]+`])]), content)
    desc := "Suspicious comment referencing an issue tracker, bug, or known vulnerability. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\bHARDCODED?\s+(?:CREDENTIALS?|PASSWORDS?|SECRETS?|KEYS?|TOKENS?)\b`]), content)
    desc := "Suspicious comment indicating hardcoded credentials or secrets. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:SKIP|DISABLE)\s+(?:TLS|SSL|VERIF(?:Y|ICATION))\b|\bDEFAULT\s+(?:ADMIN\s+)?(?:PASSWORD|CREDENTIALS?|KEY|TOKEN|SECRET)\b|\b(?:WEAK|VULNERABLE)\s+(?:PASSWORD|CREDENTIALS?|KEY|ENCRYPT(?:ION)?|CIPHER|HASH)\b|\b(?:SECURITY|AUTH(?:N|Z)?)\s+(?:BYPASS|DISABLED?|WEAK|MISSING)\b|\b(?:BROAD\s+ACCESS|0\.0\.0\.0/0)\b|\bOVERRID(?:E|ING)\s+(?:CIS|SECURITY)\b|\bNON[\-]?COMPLIANT\b`]), content)
    desc := "Suspicious comment indicating security shortcuts, insecure practices, or deferred security controls. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:INSECURE|DANGEROUS|RISKY)\b|\b(?:DO\s+NOT\s+DEPLOY|NOT\s+FOR\s+PRODUCTION|REMOVE\s+BEFORE|PLACEHOLDER)\b`]), content)
    desc := "Suspicious comment indicating insecure or dangerous configuration that should not be deployed. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:WORKAROUND|TEMP(?:ORARY)?\s+FIX|HACK)\b`]), content)
    desc := "Suspicious comment indicating a workaround or temporary fix for a known issue. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:NEEDS?\s+REVIEW|REVISIT|CLEANUP)\b`]), content)
    desc := "Suspicious comment indicating deferred review or cleanup. (CWE-546)"
} else = desc {
    regex.match(sprintf("(?i)%s", [`\b(?:CANNOT\s+CHANGE|WILL\s+BREAK|WILL\s+CAUSE)\b`]), content)
    desc := "Suspicious comment indicating known limitation or risk of breakage. (CWE-546)"
} else = desc {
    desc := "Suspicious comment indicating potential security concern or incomplete implementation. (CWE-546)"
}

# Helper to get path from parent unit block
get_parent_path(node) = path {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, n])
    n == node
    path := ub.path
} else = path {
    path := input.path
}

# Detect suspicious content in explicit Comment nodes
Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "Comment"
    content := node.content
    content != ""
    is_suspicious(content)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": get_parent_path(node),
        "description": suspicion_desc(content),
    }
}