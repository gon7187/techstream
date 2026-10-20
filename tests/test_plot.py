import unittest
import xml.etree.ElementTree as ET

from scripts.plot import sample_chart


class PlotTests(unittest.TestCase):
    def test_chart_contains_actual_series_and_escapes_units(self):
        samples = [
            {"values": [{"pid": "0C", "value": n, "unit": "<rpm>"}]}
            for n in (800, 1600, 800)
        ]
        svg = sample_chart(samples, "0C")
        root = ET.fromstring(svg)
        self.assertIn("&lt;rpm&gt;", svg)
        self.assertEqual(len(root.findall("{http://www.w3.org/2000/svg}circle")), 3)
        polyline = root.find("{http://www.w3.org/2000/svg}polyline")
        assert polyline is not None
        points = polyline.attrib["points"].split()
        self.assertGreater(
            float(points[0].split(",")[1]), float(points[1].split(",")[1])
        )
        self.assertEqual(points[0].split(",")[1], points[2].split(",")[1])
        ET.fromstring(sample_chart(samples[:1], "0C"))

    def test_chart_rejects_missing_nonfinite_and_inconsistent_units(self):
        with self.assertRaises(ValueError):
            sample_chart([], "0C")
        for values in (
            [[]],
            [[{"pid": "0C", "value": float("nan"), "unit": "rpm"}]],
            [
                [{"pid": "0C", "value": 1, "unit": "rpm"}],
                [{"pid": "0C", "value": 2, "unit": "Hz"}],
            ],
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                sample_chart([{"values": v} for v in values], "0C")


if __name__ == "__main__":
    unittest.main()
