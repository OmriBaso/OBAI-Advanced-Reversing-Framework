using System.Diagnostics;
using System.DirectoryServices;
using System.Text.Json;
using OBAIAgent.Models;

namespace OBAIAgent.Executors;

public static class ADEnumerator
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static Task<TaskResult> ExecuteAsync(TaskMessage task, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        string queryType = task.Parameters?.GetValueOrDefault("query_type", "domain_info") ?? "domain_info";
        string? filter = task.Parameters?.GetValueOrDefault("filter", null);
        string? searchBase = task.Parameters?.GetValueOrDefault("search_base", null);

        try
        {
            object? result = queryType.ToLower() switch
            {
                "domain_info" => GetDomainInfo(),
                "users" => QueryObjects("(&(objectCategory=person)(objectClass=user))", filter,
                    new[] { "sAMAccountName", "displayName", "mail", "memberOf", "whenCreated",
                            "lastLogon", "userAccountControl", "description", "distinguishedName" },
                    searchBase),
                "groups" => QueryObjects("(objectCategory=group)", filter,
                    new[] { "sAMAccountName", "description", "member", "managedBy",
                            "groupType", "distinguishedName" },
                    searchBase),
                "computers" => QueryObjects("(objectCategory=computer)", filter,
                    new[] { "cn", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp",
                            "dNSHostName", "description", "distinguishedName" },
                    searchBase),
                "ous" => QueryObjects("(objectCategory=organizationalUnit)", filter,
                    new[] { "name", "description", "distinguishedName", "gpLink" },
                    searchBase),
                "gpos" => QueryObjects("(objectCategory=groupPolicyContainer)", filter,
                    new[] { "displayName", "gPCFileSysPath", "flags", "versionNumber",
                            "whenCreated", "distinguishedName" },
                    searchBase),
                "domain_admins" => GetGroupMembers("Domain Admins"),
                "enterprise_admins" => GetGroupMembers("Enterprise Admins"),
                "domain_controllers" => QueryObjects(
                    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    null,
                    new[] { "cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "distinguishedName" },
                    searchBase),
                "spns" => QueryObjects(
                    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                    null,
                    new[] { "sAMAccountName", "servicePrincipalName", "memberOf", "distinguishedName" },
                    searchBase),
                "kerberoastable" => QueryObjects(
                    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                    null,
                    new[] { "sAMAccountName", "servicePrincipalName", "memberOf", "adminCount", "distinguishedName" },
                    searchBase),
                "asreproastable" => QueryObjects(
                    "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                    null,
                    new[] { "sAMAccountName", "memberOf", "distinguishedName" },
                    searchBase),
                "trusts" => GetDomainTrusts(),
                "custom_ldap" => CustomLdapQuery(task.Command, searchBase),
                _ => throw new ArgumentException($"Unknown AD query type: {queryType}"),
            };

            string output = JsonSerializer.Serialize(result, JsonOpts);
            return Task.FromResult(new TaskResult
            {
                TaskId = task.TaskId,
                Success = true,
                Output = output,
                StructuredData = result,
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = $"{ex.GetType().Name}: {ex.Message}",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            });
        }
    }

    private static Dictionary<string, object?> GetDomainInfo()
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        string defaultNC = rootDse.Properties["defaultNamingContext"].Value?.ToString() ?? "";
        string configNC = rootDse.Properties["configurationNamingContext"].Value?.ToString() ?? "";
        string schemaNC = rootDse.Properties["schemaNamingContext"].Value?.ToString() ?? "";
        string forest = rootDse.Properties["rootDomainNamingContext"].Value?.ToString() ?? "";
        string serverName = rootDse.Properties["dnsHostName"]?.Value?.ToString() ?? "";

        using var domainEntry = new DirectoryEntry($"LDAP://{defaultNC}");
        string domainDns = "";
        try { domainDns = domainEntry.Properties["dc"]?.Value?.ToString() ?? ""; } catch { }

        return new Dictionary<string, object?>
        {
            ["default_naming_context"] = defaultNC,
            ["configuration_nc"] = configNC,
            ["schema_nc"] = schemaNC,
            ["forest_root"] = forest,
            ["dc_server"] = serverName,
            ["domain_dn"] = defaultNC,
            ["functional_level"] = rootDse.Properties["domainFunctionality"]?.Value?.ToString(),
            ["forest_functional_level"] = rootDse.Properties["forestFunctionality"]?.Value?.ToString(),
        };
    }

    private static List<Dictionary<string, object?>> QueryObjects(
        string ldapFilter, string? nameFilter, string[] properties, string? searchBase)
    {
        if (!string.IsNullOrEmpty(nameFilter))
        {
            ldapFilter = $"(&{ldapFilter}(|(sAMAccountName=*{EscapeLdap(nameFilter)}*)(cn=*{EscapeLdap(nameFilter)}*)(displayName=*{EscapeLdap(nameFilter)}*)))";
        }

        string baseDn = searchBase ?? GetDefaultNC();
        using var entry = new DirectoryEntry($"LDAP://{baseDn}");
        using var searcher = new DirectorySearcher(entry, ldapFilter, properties, SearchScope.Subtree)
        {
            PageSize = 1000,
            SizeLimit = 500,
        };

        var results = new List<Dictionary<string, object?>>();

        foreach (SearchResult sr in searcher.FindAll())
        {
            var item = new Dictionary<string, object?>();
            foreach (string prop in properties)
            {
                if (sr.Properties.Contains(prop))
                {
                    var vals = sr.Properties[prop];
                    if (vals.Count == 1)
                        item[prop] = ConvertAdValue(vals[0]);
                    else if (vals.Count > 1)
                        item[prop] = vals.Cast<object>().Select(ConvertAdValue).ToList();
                    else
                        item[prop] = null;
                }
            }
            results.Add(item);
        }

        return results;
    }

    private static List<Dictionary<string, object?>> GetGroupMembers(string groupName)
    {
        string baseDn = GetDefaultNC();
        string filter = $"(&(objectCategory=group)(sAMAccountName={EscapeLdap(groupName)}))";

        using var entry = new DirectoryEntry($"LDAP://{baseDn}");
        using var searcher = new DirectorySearcher(entry, filter, new[] { "member" }, SearchScope.Subtree);
        var sr = searcher.FindOne();
        if (sr == null) return new List<Dictionary<string, object?>>();

        var members = new List<Dictionary<string, object?>>();
        foreach (var memberDn in sr.Properties["member"])
        {
            string dn = memberDn?.ToString() ?? "";
            try
            {
                using var memberEntry = new DirectoryEntry($"LDAP://{dn}");
                members.Add(new Dictionary<string, object?>
                {
                    ["distinguishedName"] = dn,
                    ["sAMAccountName"] = memberEntry.Properties["sAMAccountName"]?.Value?.ToString(),
                    ["objectClass"] = memberEntry.SchemaClassName,
                    ["displayName"] = memberEntry.Properties["displayName"]?.Value?.ToString(),
                });
            }
            catch
            {
                members.Add(new Dictionary<string, object?> { ["distinguishedName"] = dn });
            }
        }

        return members;
    }

    private static List<Dictionary<string, object?>> GetDomainTrusts()
    {
        string baseDn = GetDefaultNC();
        string filter = "(objectClass=trustedDomain)";
        string[] props = { "name", "trustDirection", "trustType", "trustAttributes",
                           "flatName", "securityIdentifier", "distinguishedName" };

        return QueryObjects(filter, null, props, baseDn);
    }

    private static List<Dictionary<string, object?>> CustomLdapQuery(string ldapFilter, string? searchBase)
    {
        if (string.IsNullOrWhiteSpace(ldapFilter))
            throw new ArgumentException("LDAP filter is required for custom_ldap query type");

        string baseDn = searchBase ?? GetDefaultNC();
        using var entry = new DirectoryEntry($"LDAP://{baseDn}");
        using var searcher = new DirectorySearcher(entry, ldapFilter) { PageSize = 1000, SizeLimit = 500 };

        var results = new List<Dictionary<string, object?>>();
        foreach (SearchResult sr in searcher.FindAll())
        {
            var item = new Dictionary<string, object?>();
            foreach (string prop in sr.Properties.PropertyNames)
            {
                var vals = sr.Properties[prop];
                if (vals.Count == 1)
                    item[prop] = ConvertAdValue(vals[0]);
                else if (vals.Count > 1)
                    item[prop] = vals.Cast<object>().Select(ConvertAdValue).ToList();
            }
            results.Add(item);
        }
        return results;
    }

    private static string GetDefaultNC()
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        return rootDse.Properties["defaultNamingContext"].Value?.ToString() ?? "";
    }

    private static object? ConvertAdValue(object? val) => val switch
    {
        byte[] bytes when bytes.Length == 16 => new Guid(bytes).ToString(),
        byte[] bytes => Convert.ToBase64String(bytes),
        long ticks when ticks > 116444736000000000 => DateTime.FromFileTimeUtc(ticks).ToString("o"),
        _ => val?.ToString(),
    };

    private static string EscapeLdap(string input)
    {
        return input
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }
}
