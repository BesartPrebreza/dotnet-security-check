using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;

const string Usage = "Usage: dotnet-security-check scan <Web.config> [--json]";
if (args is ["--help"] or ["-h"])
{
    Console.WriteLine(Usage);
    return 0;
}
if (args.Length is < 2 or > 3 || args[0] != "scan" ||
    (args.Length == 3 && args[2] != "--json"))
{
    Console.Error.WriteLine(Usage);
    return 2;
}

ScanResult result;
try
{
    using var input = File.OpenRead(args[1]);
    using var reader = XmlReader.Create(input, new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = 8_000_000
    });
    result = Scanner.Scan(XDocument.Load(reader, LoadOptions.SetLineInfo));
}
catch (XmlException error)
{
    // Parser diagnostics can contain source values. Emit only the location.
    Console.Error.WriteLine($"Invalid or unsupported XML at line {error.LineNumber}, column {error.LinePosition}.");
    return 2;
}
catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
{
    Console.Error.WriteLine("Could not read the configuration file.");
    return 2;
}
catch (InvalidDataException)
{
    Console.Error.WriteLine("Expected a deployed Web.config with an unqualified configuration root and no XDT directives.");
    return 2;
}

if (args.Length == 3)
{
    Console.WriteLine(JsonSerializer.Serialize(result, ScanJsonContext.Default.ScanResult));
}
else
{
    foreach (var finding in result.Findings)
    {
        Console.WriteLine($"[{finding.Severity}] {finding.Id} line {finding.Line} — {finding.Message}");
        Console.WriteLine($"  {finding.Remediation}");
    }
    foreach (var limitation in result.Limitations)
    {
        Console.WriteLine($"[INCOMPLETE] line {limitation.Line} — {limitation.Message}");
    }
    Console.WriteLine($"{result.Findings.Count} finding(s), {result.Limitations.Count} incomplete section(s).");
}
return result.Limitations.Count > 0 ? 2 : result.Findings.Count > 0 ? 1 : 0;

internal static class Scanner
{
    private static readonly XNamespace Xdt = "http://schemas.microsoft.com/XML-Document-Transform";
    private static readonly HashSet<string> SecretKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "pwd", "clientsecret", "apikey", "accesstoken", "refreshtoken",
        "authtoken", "secretkey", "accountkey", "privatekey", "signingkey",
        "sharedaccesskey", "sharedaccesssignature", "secret", "token"
    };

    internal static ScanResult Scan(XDocument document)
    {
        var root = document.Root;
        if (root?.Name != "configuration" ||
            root.DescendantsAndSelf().Any(element => element.Attributes().Any(a => a.Name.Namespace == Xdt)))
        {
            throw new InvalidDataException();
        }

        var findings = new List<Finding>();
        var limitations = new List<Limitation>();
        foreach (var scope in root.Elements("location").Prepend(root))
        {
            if (scope.Element("system.web") is { } web)
            {
                Check(web, "compilation", "debug", "true", "DSC001", "medium",
                    "ASP.NET debug mode is enabled.", "Disable debug compilation in the deployed configuration.");
                Check(web, "customErrors", "mode", "Off", "DSC002", "high",
                    "ASP.NET custom errors are disabled.", "Set customErrors mode to On or RemoteOnly.");
                Check(web, "httpCookies", "requireSSL", "false", "DSC004", "medium",
                    "The ASP.NET cookie defaults allow cookies without the Secure flag.",
                    "Set requireSSL to true for HTTPS deployments and review application-level cookie overrides.");
                Check(web, "httpCookies", "httpOnlyCookies", "false", "DSC004", "medium",
                    "The ASP.NET cookie defaults allow cookies without HttpOnly.",
                    "Enable httpOnlyCookies and review any intentional per-cookie exceptions.");
            }

            if (scope.Element("system.webServer") is { } server)
            {
                Check(server, "httpErrors", "errorMode", "Detailed", "DSC003", "high",
                    "IIS is configured to return detailed HTTP errors.",
                    "Set errorMode to Custom or DetailedLocalOnly and review application error responses separately.");
            }

            foreach (var section in scope.Elements().Where(e => e.Name == "appSettings" || e.Name == "connectionStrings"))
            {
                RecordExternal(section);
                foreach (var item in section.Elements("add"))
                {
                    var hasSecret = section.Name == "appSettings"
                        ? IsSecretKey((string?)item.Attribute("key") ?? "") &&
                          IsLiteral((string?)item.Attribute("value") ?? "")
                        : ConnectionHasSecret((string?)item.Attribute("connectionString") ?? "", item, limitations);
                    if (hasSecret)
                    {
                        findings.Add(new Finding("DSC005", "high", Line(item),
                            "A possible credential is stored directly in the configuration.",
                            "Use a deployment-managed secret or an appropriate protected configuration mechanism."));
                    }
                }
            }
        }
        return new ScanResult(findings.OrderBy(f => f.Line).ThenBy(f => f.Id).ToList(),
            limitations.OrderBy(l => l.Line).ToList());

        void Check(XElement parent, string section, string attribute, string value, string id,
            string severity, string message, string remediation)
        {
            if (parent.Element(section) is not { } node) return;
            if (attribute != "httpOnlyCookies") RecordExternal(node);
            var setting = node.Attribute(attribute);
            if (string.Equals(setting?.Value.Trim(), value, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding(id, severity, Line(setting!), message, remediation));
            }
        }

        void RecordExternal(XElement node)
        {
            if (node.Attribute("configSource") is not null || node.Attribute("configProtectionProvider") is not null ||
                (node.Name == "appSettings" && node.Attribute("file") is not null))
            {
                limitations.Add(new Limitation(Line(node), $"External or protected {node.Name.LocalName} content was not inspected."));
            }
        }
    }

    private static bool ConnectionHasSecret(string value, XElement item, List<Limitation> limitations, int depth = 0)
    {
        if (!IsLiteral(value)) return false;
        if (depth >= 3)
        {
            limitations.Add(new Limitation(Line(item), "A nested connection string exceeded the supported depth."));
            return false;
        }
        var builder = new DbConnectionStringBuilder();
        try { builder.ConnectionString = value; }
        catch (ArgumentException)
        {
            limitations.Add(new Limitation(Line(item), "A connection string could not be parsed."));
            return false;
        }

        return builder.Keys.Cast<string>().Any(key =>
        {
            var part = builder[key]?.ToString() ?? "";
            return key.Equals("provider connection string", StringComparison.OrdinalIgnoreCase)
                ? ConnectionHasSecret(part, item, limitations, depth + 1)
                : IsSecretKey(key) && IsLiteral(part);
        });
    }

    private static bool IsSecretKey(string key)
    {
        var normalized = new string(key.Where(char.IsLetterOrDigit).ToArray());
        return SecretKeys.Contains(normalized) ||
            SecretKeys.Any(secret => secret.Length >= 6 && normalized.EndsWith(secret, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLiteral(string value)
    {
        value = value.Trim();
        return value.Length > 0 &&
            !(value.StartsWith("${", StringComparison.Ordinal) && value.EndsWith('}')) &&
            !(value.StartsWith("$(", StringComparison.Ordinal) && value.EndsWith(')')) &&
            !(value.StartsWith("#{", StringComparison.Ordinal) && value.EndsWith("}#", StringComparison.Ordinal)) &&
            !value.StartsWith("@Microsoft.KeyVault(", StringComparison.OrdinalIgnoreCase);
    }

    private static int Line(XObject node) => ((IXmlLineInfo)node).LineNumber;
}

internal sealed record Finding(string Id, string Severity, int Line, string Message, string Remediation);
internal sealed record Limitation(int Line, string Message);
internal sealed record ScanResult(List<Finding> Findings, List<Limitation> Limitations);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(ScanResult))]
internal sealed partial class ScanJsonContext : JsonSerializerContext;
