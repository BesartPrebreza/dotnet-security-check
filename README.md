# .NET Security Check

A local, read-only C# CLI for reviewing the published Web.config of classic ASP.NET applications on .NET Framework. Scan the output of your Release publish step to see settings after deployment transforms have been applied.

## Try it

With the .NET 10 SDK installed, run from the repository root.

```sh
dotnet build -c Release
dotnet bin/Release/net10.0/dotnet-security-check.dll scan demo/publish/Web.config
```

The synthetic source configuration uses `RemoteOnly`. The sample Release transform changes it to `Off`. The repository includes the resulting configuration in `demo/publish/` so the demo runs on any platform with the SDK.

```text
[high] DSC002 line 4 — ASP.NET custom errors are disabled.
  Set customErrors mode to On or RemoteOnly.
1 finding(s), 0 incomplete section(s).
```

## Checks

| Rule | Looks for |
|---|---|
| DSC001 | ASP.NET debug compilation explicitly enabled |
| DSC002 | ASP.NET custom errors explicitly disabled |
| DSC003 | IIS detailed HTTP errors explicitly enabled |
| DSC004 | Explicitly disabled Secure or HttpOnly cookie defaults |
| DSC005 | Possible literal credentials in app settings or connection strings |

The tool emits rule IDs and source line numbers. It keeps configuration values, credential keys, and input paths out of reports and diagnostics. It does not modify the input or contact a target. For automation, append `--json` to receive findings and limitations as JSON.

| Exit code | Meaning |
|---|---|
| 0 | Scan completed with no matches in the supported checks |
| 1 | Scan completed and found at least one match |
| 2 | Invalid usage, unreadable input, or an incomplete scan |

## Scope

The scanner reads explicit declarations in a single published file, including its direct location blocks. It does not resolve inherited IIS or machine-level settings, apply XDT transforms, read referenced sections, decrypt protected sections, or inspect application code. A clean scan covers only the five rules and the settings present in the file. External or protected content in a checked section is reported as incomplete. Credential detection is heuristic. Review findings before making changes.

## Verify

```sh
dotnet build -c Release
python3 tests/smoke.py
```

The GitHub Actions workflow repeats the build and smoke tests on Windows and Linux. The smoke tests use only synthetic configuration data.
