"""VIN decoder and ISO 3779 check digit."""
import unittest

from base import ev  # noqa: F401  (sets sys.path)
from ids_siem import vin


def make(c5="M", c6="1", c7="A", c8="A", c10="T", c11="F", serial="000001", wmi="SC6"):
    b = wmi + "G" + c5 + c6 + c7 + c8 + "0" + c10 + c11 + serial
    return b[:8] + vin.check_digit(b) + b[9:]


class TestVin(unittest.TestCase):
    def test_check_digit_reference_vector(self):
        # Well-known example VIN from ISO 3779 / 49 CFR 565: 1M8GDM9AXKP042788 has check digit X
        self.assertEqual(vin.check_digit("1M8GDM9AXKP042788"), "X")

    def test_decode_eu(self):
        d = vin.decode(make())
        self.assertTrue(d["valid"] and d["check_ok"])
        self.assertEqual((d["market"], d["year"], d["drive"]), ("EU/ROW", 2026, "LHD"))
        self.assertEqual(d["unknown"], [])

    def test_decode_us(self):
        d = vin.decode(make(c7="C"))
        self.assertEqual(d["market"], "US/Canada")

    def test_wrong_check_digit_detected(self):
        v = make()
        bad = v[:8] + ("0" if v[8] != "0" else "1") + v[9:]
        self.assertFalse(vin.decode(bad)["check_ok"])

    def test_malformed_vin(self):
        for v in ("", "SHORT", "SC6GM1AA7TF00000I", "SC6GM1AA7TF0000012"):  # empty, short, forbidden letter I, 18 chars
            d = vin.decode(v)
            self.assertFalse(d["valid"], v)

    def test_lowercase_normalised(self):
        self.assertEqual(vin.decode(make().lower())["vin"], make())

    def test_unknown_code_reported_not_raised(self):
        d = vin.decode(make(c7="Z"))
        self.assertTrue(d["valid"])
        self.assertTrue(any("engine" in u for u in d["unknown"]))


if __name__ == "__main__":
    unittest.main()
