"""Decode INEOS Grenadier VINs.

Source: "INEOS Grenadier VIN Decoder Global", document Corp-P2-ENG-0128 rev 001 (07 Jun 2024).
It has five tables: EU/ROW serial, EU/ROW SVO, US/Canada MPV serial, US/Canada truck, US/Canada MPV SVO.

Position map (1-based):  1-3 WMI | 4 make (G) | 5 line | 6 body | 7 engine | 8 hand of drive (EU/ROW)
or GVWR and restraints (US) | 9 check digit | 10 model year | 11 plant | 12-17 serial number.

Values the document does not list are never guessed: they decode to "Unknown (X)" and are
reported in `unknown`, so a new variant shows up instead of being silently mislabelled.
"""
import re

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")  # I, O and Q are not allowed in a VIN

LINE = {  # position 5 together with position 4 = G
    "N": ("N1G", "Serial production"),
    "M": ("M1G", "Serial production"),
    "1": ("M1G", "SVO"),
}
BODY = {"1": "LWB multipurpose passenger vehicle", "2": "LWB van", "3": "XLWB pickup", "4": "XLWB chassis cab"}
BODY_US = {"1": "Station wagon", "3": "Pickup (double cab)"}
ENGINE = {  # code: (fuel, emission standard)
    "A": ("Petrol", "EU6d"), "B": ("Petrol", "EU4"), "C": ("Petrol", "LEVIII"),
    "D": ("Diesel", "EU6d"), "E": ("Diesel", "EU4"),
}
DRIVE = {"A": "LHD", "B": "RHD"}
YEAR = {"N": 2022, "P": 2023, "R": 2024, "S": 2025, "T": 2026, "V": 2027, "W": 2028}
PLANT = {"F": "France (Hambach)"}
US_GVWR = "3500 kg (class F), 3-point belts at all positions, frontal, knee, side and curtain airbags"

_TRANSLIT = {**{str(i): i for i in range(10)},
             **dict(zip("ABCDEFGH", range(1, 9))), **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9,
             **dict(zip("STUVWXYZ", range(2, 10)))}
_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def check_digit(vin):
    """ISO 3779 / 49 CFR 565 check digit. The decoder only says 'Calculation' (EU) or 'Reserved' (US)."""
    total = sum(_TRANSLIT[c] * w for c, w in zip(vin, _WEIGHTS))
    r = total % 11
    return "X" if r == 10 else str(r)


def _unknown(code):
    return f"Unknown ({code})"


def decode(vin):
    """Return a dict of decoded facts, or {"valid": False, "problem": ...} for a malformed VIN."""
    v = (vin or "").strip().upper()
    if not VIN_RE.match(v):
        return {"vin": v, "valid": False, "problem": "Not a 17-character VIN", "label": "Not decodable"}
    wmi, c4, c5, c6, c7, c8, c9, c10, c11, serial = v[:3], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11:]
    unknown = []

    def look(table, code, what):
        if code in table:
            return table[code]
        unknown.append(f"{what} {code}")
        return None

    truck = wmi == "SH7"
    if wmi not in ("SC6", "SH7"):
        unknown.append(f"WMI {wmi}")
    if c4 != "G":
        unknown.append(f"make {c4}")
    line = look(LINE, c5, "line")
    vtype, variant = line if line else (None, None)
    # The EU/ROW tables also list the LEVIII engine, so those VINs are not told apart from US/Canada
    # by structure alone. A passenger car with engine C and restraint code A matches the US/Canada
    # MPV tables exactly, so it is reported as US/Canada. Trucks use their own WMI (SH7).
    us = truck or (c5 in "M1" and c6 == "1" and c7 == "C" and c8 == "A")
    market = "US/Canada" if us else "EU/ROW"

    body = (BODY_US if us and c6 in BODY_US else BODY).get(c6)
    if body is None:
        unknown.append(f"body {c6}")
    eng = look(ENGINE, c7, "engine")
    fuel, emission = eng if eng else (None, None)
    drive = gvwr = None
    if us:
        if c8 == "A":
            gvwr = US_GVWR + (", hydraulic brake system" if truck else "")
        else:
            unknown.append(f"GVWR/restraints {c8}")
    else:
        drive = look(DRIVE, c8, "hand of drive")
    year = look(YEAR, c10, "model year")
    plant = look(PLANT, c11, "plant")

    expected = check_digit(v)
    # Only the EU/ROW tables define the check digit; the US tables list it as reserved.
    check_ok = c9 == expected

    parts = [str(year) if year else None, body.split(" (")[0] if body else None,
             f"{fuel} {emission}" if fuel else None, drive]
    label = ", ".join(x for x in parts if x) or "Not decodable"
    return {
        "vin": v, "valid": True, "wmi": wmi, "manufacturer": "INEOS Automotive", "model": "Grenadier",
        "market": market, "variant": variant, "vehicle_type": vtype,
        "body": body or _unknown(c6), "fuel": fuel or _unknown(c7), "emission": emission or _unknown(c7),
        "engine": f"{fuel} {emission}" if fuel else _unknown(c7),
        "drive": drive or (None if us else _unknown(c8)), "gvwr": gvwr,
        "year": year, "plant": plant or _unknown(c11), "serial": serial,
        "check_digit": c9, "check_expected": expected, "check_ok": check_ok,
        "unknown": unknown, "label": label,
    }


# Attributes a user can group or filter by: key in decode() output -> display name.
DIMENSIONS = {
    "year": "Model year", "variant": "Variant", "vehicle_type": "Vehicle type", "body": "Body",
    "engine": "Engine", "drive": "Hand of drive", "market": "Market", "plant": "Plant",
}


def dim_value(info, dim):
    """Value of one dimension as a string; 'Not decodable' for malformed VINs, 'n/a' where it does not apply."""
    if not info.get("valid"):
        return "Not decodable"
    x = info.get(dim)
    return "n/a" if x in (None, "") else str(x)
