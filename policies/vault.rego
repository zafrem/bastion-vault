package vault

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Bastion Vault OPA Policy — SRS §3.5 RBAC Enforcement
# ---------------------------------------------------------------------------

default allow := false
default access_level := "none"

# ---------------------------------------------------------------------------
# allow: top-level decision
# ---------------------------------------------------------------------------

allow if {
    level := resolved_access_level
    level != "none"
}

# ---------------------------------------------------------------------------
# resolved_access_level: effective access level for (subject, resource)
# ---------------------------------------------------------------------------

resolved_access_level := level if {
    level := rbac_matrix[input.subject.department][input.subject.role][input.resource.category]
    level != "none"
}

# ---------------------------------------------------------------------------
# RBAC Matrix — mirrors internal/access/controller.go
# ---------------------------------------------------------------------------

rbac_matrix := {
    "marketing": {
        "manager": {
            "DC-01": "full",
            "DC-02": "read",
            "DC-03": "aggregated"
        },
        "analyst": {
            "DC-01": "k_anonymized",
            "DC-02": "k_anonymized",
            "DC-03": "aggregated"
        }
    },
    "manufacturing": {
        "manager": {
            "DC-01": "slice",
            "DC-02": "full",
            "DC-03": "none"
        },
        "staff": {
            "DC-01": "slice",
            "DC-02": "full",
            "DC-03": "none"
        }
    },
    "hr": {
        "manager": {
            "DC-01": "none",
            "DC-02": "none",
            "DC-03": "full"
        },
        "staff": {
            "DC-01": "none",
            "DC-02": "none",
            "DC-03": "anonymized"
        }
    },
    "executive": {
        "executive": {
            "DC-01": "aggregated",
            "DC-02": "aggregated",
            "DC-03": "aggregated"
        }
    },
    "audit": {
        "auditor": {
            "DC-01": "audit_log",
            "DC-02": "audit_log",
            "DC-03": "audit_log"
        }
    }
}

# ---------------------------------------------------------------------------
# deanonymize: only certain roles may call the deanonymize endpoint
# ---------------------------------------------------------------------------

deanonymize_allowed if {
    input.subject.department == "marketing"
    input.subject.role == "manager"
    input.resource.category == "DC-01"
}

deanonymize_allowed if {
    input.subject.department == "hr"
    input.subject.role == "manager"
    input.resource.category == "DC-03"
}

# ---------------------------------------------------------------------------
# break_glass: validates an active break-glass token
# ---------------------------------------------------------------------------

break_glass_valid if {
    token := input.break_glass_token
    token != ""
    # In production, verify token signature and expiry via external data.
    # Here we delegate to the Go service layer.
    token != "INVALID"
}

# ---------------------------------------------------------------------------
# k_threshold: returns the required K for a data category
# ---------------------------------------------------------------------------

k_threshold := 5  if { input.resource.category == "DC-01" }
k_threshold := 3  if { input.resource.category == "DC-02" }
k_threshold := 10 if { input.resource.category == "DC-03" }

# ---------------------------------------------------------------------------
# sensitivity constraints: enforce minimum sensitivity handling
# ---------------------------------------------------------------------------

sensitivity_level_ok if {
    input.action == "read"
    resolved_access_level in {"full", "read", "anonymized", "k_anonymized", "slice", "aggregated", "audit_log"}
}

sensitivity_level_ok if {
    input.action == "anonymize"
}

sensitivity_level_ok if {
    input.action == "deanonymize"
    deanonymize_allowed
}
