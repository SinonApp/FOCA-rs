#!/usr/bin/env python3
"""Unit tests of `update_nvd.py` on a small fixture feed (no network).

Run: python3 crates/foca-analysis/signatures/tools/test_update_nvd.py
"""

import io
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import update_nvd as u  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "nvd_mini.json"
TOML = '''
[[software]]
id = "{app_id}"
name = "x"
cpe = "microsoft:office microsoft:{app_lc}"
re = "x"

[[os]]
id = "win7"
name = "Windows 7"
cpe = "microsoft:windows_7"
re = "x"
'''


class FeedTests(unittest.TestCase):
    def cves(self, chunk=64):
        return list(u.iter_feed(io.BytesIO(FIXTURE.read_bytes()), chunk=chunk))

    def test_stream_parser_yields_every_cve_with_tiny_chunks(self):
        self.assertEqual([c["id"] for c in self.cves(7)],
                         [f"CVE-2099-000{i}" for i in range(1, 6)])

    def test_cpe_fields_honour_escapes(self):
        f = u.cpe_fields("cpe:2.3:a:example_vendor:shop_x:*:*:*:*:*:joomla\\!:*:*")
        self.assertEqual(u.cms_of(f[10]), "joomla")
        self.assertEqual(u.cpe_key("cpe:/a:f5:nginx:1.0"), "f5:nginx")

    def test_ranges(self):
        self.assertEqual(u.range_of({"versionStartIncluding": "1.1", "versionEndExcluding": "2"}, "*"), "[1.1,2)")
        self.assertEqual(u.range_of({"versionStartExcluding": "2.0"}, "*"), "(2.0,)")
        self.assertEqual(u.range_of({"versionEndIncluding": "5.4"}, "*"), "[,5.4]")
        self.assertEqual(u.range_of({}, "-"), "*")
        self.assertEqual(u.range_of({}, "0.9.7"), "=0.9.7")

    def test_bounded_entries_win_over_an_unbounded_one(self):
        def m(crit, **k):
            return {"vulnerable": True, "criteria": crit, **k}
        cve = {"configurations": [
            {"nodes": [{"cpeMatch": [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="143.0.1")]}]},
            {"nodes": [{"cpeMatch": [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")]}]},
            {"nodes": [{"cpeMatch": [m("cpe:2.3:a:google:chrome:49.0.2623.87:*:*:*:*:*:*:*")]}]},
        ]}
        got = u.product_ranges(cve, {"google:chrome": {"s"}})
        self.assertEqual(got["google:chrome"], ["=49.0.2623.87", "[,143.0.1)"])
        only = {"configurations": [{"nodes": [{"cpeMatch": [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")]}]}]}
        self.assertEqual(u.product_ranges(only, {"google:chrome": {"s"}})["google:chrome"], ["*"])

    def test_software_cpes_expand_office_apps(self):
        got = u.software_cpes(TOML)
        self.assertEqual(got["microsoft:word"], {"d"})
        self.assertEqual(got["microsoft:windows_7"], {"o"})

    def test_build_keeps_only_wanted_products(self):
        wanted = u.wanted_products([{"n": "Nginx", "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}],
                                   TOML + '\n[[software]]\nid="o365"\nname="x"\ncpe="microsoft:365_apps"\nre="x"\n',
                                   set())
        text, st = u.build([self.cves()], wanted, {"CVE-2099-0001"}, {"CVE-2099-0002": 0.1234},
                           {"snapshot": "2099-06-01", "epss": "2099-06-01"})
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("# foca-nvd v1 snapshot=2099-06-01"))
        self.assertIn("C\t2099-0001\t2099\t9.8\t31\t20,787\tK\t", lines)
        self.assertIn("C\t2099-0002\t2099\t5.3\t40\t79\t\t1234", lines)
        self.assertIn("C\t2099-0004\t2099\t4.3\t2\t\t\t", lines)
        self.assertNotIn("2099-0003", text)  # rejected
        self.assertNotIn("2099-0005", text)  # unrelated product only
        self.assertNotIn("unrelated", text)
        self.assertNotIn("linux_kernel", text)  # vulnerable=false platform
        i = lines.index("P\tf5:nginx\ts")
        self.assertEqual(lines[i + 1], "0\t=0.9.7 [1.1.0,1.20.1)")
        self.assertIn("P\texample_vendor:contact_form_x@wordpress\tp", lines)
        self.assertIn("P\texample_vendor:shop_x@joomla\tp", lines)
        j = lines.index("P\tmicrosoft:office\td")
        self.assertEqual(lines[j + 1], "2\t=2016")
        self.assertEqual(lines[lines.index("P\tmicrosoft:365_apps\td") + 1], "2\t*")
        self.assertEqual((st["cves"], st["site"], st["plugin"], st["doc"], st["kev"]), (3, 1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
