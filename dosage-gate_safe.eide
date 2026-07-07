#! Dosage gate — untrusted an order can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires approveDose — the dosage gate sink
#! @effect io
#! @confidence 80
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant approveDose irreversible confidence 80

type DoseBand = LowDose | StdDose | HighDose
type Decision = ApproveDose(DoseBand) | RejectDose

let raw = fetch<web>  # UNTRUSTED an order — tainted
quarantined { let d = extract<Decision>(raw) confidence 80 }  # only a fixed Decision (payloads too) crosses
commit { approveDose(d) }  # act on the trusted decision only
