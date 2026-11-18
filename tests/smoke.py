"""Exercise the built CLI with isolated, synthetic configurations."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOTNET = sys.argv.pop(1) if len(sys.argv) > 1 else "dotnet"
DLL = ROOT / "bin/Release/net10.0/dotnet-security-check.dll"


def scan(path, *flags):
    return subprocess.run([DOTNET, str(DLL), "scan", str(path), *flags],
                          capture_output=True, text=True, check=False)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "Web.config"

    def fixture(self, xml, *flags):
        self.path.write_text(xml, encoding="utf-8")
        return scan(self.path, *flags)

    def test_release_fixture(self):
        self.assertEqual(scan(ROOT / "demo/Web.config").returncode, 0)
        result = scan(ROOT / "demo/publish/Web.config", "--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual([f["id"] for f in json.loads(result.stdout)["findings"]], ["DSC002"])
        self.assertEqual(scan(ROOT / "demo/Web.Release.config").returncode, 2)

    def test_rules_and_redaction(self):
        result = self.fixture("""<configuration><location path="example">
          <system.web><compilation debug="true"/><customErrors mode="Off"/>
            <httpCookies requireSSL="false" httpOnlyCookies="false"/></system.web>
          <system.webServer><httpErrors errorMode="Detailed"/></system.webServer>
          <appSettings><add key="Service:ApiKey" value="synthetic-secret"/>
            <add key="ClientSecret" value="${DEPLOY_SECRET}"/></appSettings>
          <connectionStrings><add connectionString="Server=localhost;Password='synthetic;password'"/>
            <add connectionString="provider connection string=&quot;Password=synthetic-nested&quot;"/>
          </connectionStrings>
        </location></configuration>""", "--json")
        self.assertEqual(result.returncode, 1)
        self.assertCountEqual([f["id"] for f in json.loads(result.stdout)["findings"]],
                              ["DSC001", "DSC002", "DSC003", "DSC004", "DSC004",
                               "DSC005", "DSC005", "DSC005"])
        self.assertNotIn("synthetic", result.stdout + result.stderr)

    def test_incomplete_sections_are_reported(self):
        result = self.fixture("""<configuration><appSettings file="never-open.config"/>
          <system.web><customErrors configSource="never-open.config"/></system.web>
          <connectionStrings><add connectionString="synthetic-invalid"/></connectionStrings>
        </configuration>""", "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(json.loads(result.stdout)["limitations"]), 3)
        self.assertNotIn("synthetic-invalid", result.stdout + result.stderr)

    def test_invalid_input_never_echoes_values(self):
        for xml in ['<!DOCTYPE configuration><configuration/>',
                    '<configuration><synthetic-secret></configuration>', '<wrong/>']:
            with self.subTest(xml=xml):
                result = self.fixture(xml)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("synthetic-secret", result.stdout + result.stderr)
        self.assertEqual(scan(self.path.with_name("missing.config")).returncode, 2)

    def test_empty_application_config_does_not_claim_effective_settings(self):
        result = self.fixture("<configuration/>", "--json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"findings": [], "limitations": []})


if __name__ == "__main__":
    unittest.main()
