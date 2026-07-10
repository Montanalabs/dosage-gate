#! VULNERABLE dosage-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant approveDose irreversible confidence 80

let raw = fetch<web>
commit { approveDose(raw) }  # tainted -> tool: REJECTED
