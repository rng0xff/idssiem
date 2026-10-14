"""Event catalog: maps (report type, event id) to a readable name, category and default severity.

The severities below are STARTING POINTS chosen by event semantics, not vendor ratings.
They are editable in the UI (Catalog page) and the edits are stored in the database.
"""
import re

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_NUM = {s: i for i, s in enumerate(SEVERITIES)}

# (event_type, event_id) -> (short_name, category, severity)
DEFAULTS = {
    ("can", 32768): ("UNKNOWN_MSG", "CAN integrity", "medium"),
    ("can", 32769): ("INVLD_DLC", "CAN integrity", "medium"),
    ("can", 32772): ("FRQ_DELTA_TOO_LOW", "CAN timing", "low"),
    ("can", 32773): ("FRQ_DELTA_OVERWR", "CAN timing", "medium"),
    ("can", 32774): ("CAN_LOAD_TOO_HI", "CAN load", "medium"),
    ("can", 32775): ("FRQ_DELTA_TOO_HI", "CAN timing", "low"),
    ("can", 32776): ("FRQ_TIMEOUT", "CAN timing", "low"),
    ("can", 32778): ("INVALID_CNTR_HOLD", "CAN integrity", "medium"),
    ("can", 32780): ("INVALID_SIG", "CAN integrity", "medium"),
    ("can", 32781): ("BAD_TP_MSG", "CAN integrity", "medium"),
    ("can", 32782): ("EXCSSV_PERD_MSG", "CAN timing", "medium"),
    ("can", 32787): ("BURST_START", "IDS internal", "info"),
    ("can", 32788): ("BURST_END", "IDS internal", "info"),
    ("can", 32795): ("UDS_CRIT_NR_NRC", "Diagnostics", "high"),
    ("can", 32796): ("UDS_UNLIKELY_NR_NRC", "Diagnostics", "medium"),
    ("sev", 32809): ("Dropped_Message_CRC", "Message integrity", "low"),
    ("sev", 32810): ("Generic_RX_Fail", "ECU health", "low"),
    ("sev", 32811): ("Generic_TX_Fail", "ECU health", "low"),
    ("sev", 32812): ("TX_Queue_Full", "ECU health", "medium"),
    ("sev", 32818): ("Coding_Process_failed", "Configuration", "high"),
    ("sev", 32821): ("CPU_Load_High", "ECU health", "low"),
    ("sev", 32822): ("Immo_Pairing_Fail", "Authentication", "high"),
    ("sev", 32823): ("Immo_Auth_Fail", "Authentication", "high"),
    ("sev", 32826): ("BT_Pairing_Sequence_Fail", "Wireless", "medium"),
    ("sev", 32837): ("Generic_RX_or_TX_Fail", "ECU health", "low"),
}

AUTOSAR_TYPE = "autosarsev"


def cat_id(event_type, event_id):
    return f"{event_type}:{event_id}"


def derive_short_name(name, ecu_name, event_type, event_id):
    """Strip the IdsMEventConfig_<ECU>_ / ECY_IDPS_RPRT_ prefixes from a vendor event name."""
    n = (name or "").strip()
    if not n:
        return f"{event_type.upper()}_{event_id}"
    n = re.sub(r"^IdsMEventConfig_", "", n)
    if ecu_name:
        prefix = ecu_name.replace("-", "_") + "_"
        if n.lower().startswith(prefix.lower()):
            n = n[len(prefix):]
    n = re.sub(r"^ECY_IDPS_RPRT_", "", n)
    return n or f"{event_type.upper()}_{event_id}"


def default_for(event_type, event_id, name, ecu_name):
    """Return (short_name, category, severity, auto_flag) for an event type."""
    try:
        key = (event_type, int(event_id))
    except (TypeError, ValueError):
        key = (event_type, None)
    if key in DEFAULTS:
        short, cat, sev = DEFAULTS[key]
        return short, cat, sev, 0
    short = derive_short_name(name, ecu_name, event_type, event_id)
    if event_type == AUTOSAR_TYPE:
        return short, "AUTOSAR", "info", 0
    # Unknown type: needs analyst classification
    return short, "Unclassified", "low", 1
