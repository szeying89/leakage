from pathlib import Path
import tempfile
import unittest

import dirtyfrag_poc


class DirtyFragPocTests(unittest.TestCase):
    def test_loaded_module_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_modules = Path(tmp) / "modules"
            proc_modules.write_text("esp4 16384 0 - Live 0x0\nloop 1 0 - Live 0x0\n", encoding="utf-8")
            self.assertEqual(dirtyfrag_poc.read_loaded_modules(proc_modules), {"esp4", "loop"})

    def test_modprobe_mitigation_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "dirtyfrag.conf"
            config.write_text(
                "install esp4 /bin/false\n"
                "blacklist esp6\n"
                "install rxrpc /bin/echo not-a-block\n",
                encoding="utf-8",
            )
            self.assertEqual(
                dirtyfrag_poc.parse_modprobe_mitigations("esp4", (config,))[:2],
                (True, False),
            )
            self.assertEqual(
                dirtyfrag_poc.parse_modprobe_mitigations("esp6", (config,))[:2],
                (False, True),
            )
            self.assertEqual(
                dirtyfrag_poc.parse_modprobe_mitigations("rxrpc", (config,))[:2],
                (False, False),
            )

    def test_report_risk_is_high_when_watched_module_is_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_modules = Path(tmp) / "modules"
            proc_modules.write_text("rxrpc 20480 1 - Live 0x0\n", encoding="utf-8")
            modprobe_root = Path(tmp) / "modprobe.d"
            module_root = Path(tmp) / "module-tree"
            modprobe_root.mkdir()
            module_root.mkdir()
            report = dirtyfrag_poc.build_report(
                kernel_release="test-kernel",
                proc_modules=proc_modules,
                modprobe_roots=(modprobe_root,),
                module_roots=(module_root,),
            )
            self.assertEqual(report.risk_level, "high")
            self.assertTrue(report.any_loaded)

    def test_report_risk_is_low_when_modules_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_modules = Path(tmp) / "modules"
            proc_modules.write_text("loop 1 0 - Live 0x0\n", encoding="utf-8")
            modprobe_root = Path(tmp) / "modprobe.d"
            module_root = Path(tmp) / "module-tree"
            modprobe_root.mkdir()
            module_root.mkdir()
            report = dirtyfrag_poc.build_report(
                kernel_release="test-kernel",
                proc_modules=proc_modules,
                modprobe_roots=(modprobe_root,),
                module_roots=(module_root,),
            )
            self.assertEqual(report.risk_level, "low")
            self.assertFalse(report.any_exposed)

    def test_synthetic_telemetry_is_safe_and_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_modules = Path(tmp) / "modules"
            proc_modules.write_text("esp4 16384 0 - Live 0x0\n", encoding="utf-8")
            modprobe_root = Path(tmp) / "modprobe.d"
            module_root = Path(tmp) / "module-tree"
            modprobe_root.mkdir()
            module_root.mkdir()
            report = dirtyfrag_poc.build_report(
                kernel_release="test-kernel",
                proc_modules=proc_modules,
                modprobe_roots=(modprobe_root,),
                module_roots=(module_root,),
            )
            events = dirtyfrag_poc.build_synthetic_telemetry(report)
            self.assertGreaterEqual(len(events), 5)
            self.assertEqual(events[0]["event_type"], "process_start")
            self.assertIn("Synthetic", events[2]["note"])
            joined = "\n".join(event["command_line"] for event in events)
            self.assertNotIn("/etc/passwd", joined)
            self.assertNotIn("chmod u+s", joined)



if __name__ == "__main__":
    unittest.main()
