using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using OBAIAgent.Models;

namespace OBAIAgent.Executors;

public static class SystemInfoCollector
{
    public static Task<TaskResult> ExecuteAsync(TaskMessage task, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var info = new Dictionary<string, object?>
            {
                ["hostname"] = Environment.MachineName,
                ["domain"] = Environment.UserDomainName,
                ["username"] = Environment.UserName,
                ["os_version"] = Environment.OSVersion.ToString(),
                ["os_description"] = RuntimeInformation.OSDescription,
                ["architecture"] = RuntimeInformation.OSArchitecture.ToString(),
                ["process_architecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                ["processor_count"] = Environment.ProcessorCount,
                ["dotnet_version"] = Environment.Version.ToString(),
                ["system_directory"] = Environment.SystemDirectory,
                ["uptime_hours"] = Math.Round(Environment.TickCount64 / 3600000.0, 1),
                ["current_directory"] = Environment.CurrentDirectory,
                ["is_elevated"] = IsElevated(),
                ["network_interfaces"] = GetNetworkInfo(),
                ["environment_variables"] = GetEnvironmentVars(),
                ["drives"] = GetDriveInfo(),
                ["running_processes_count"] = Process.GetProcesses().Length,
                ["top_processes"] = GetTopProcesses(),
            };

            string json = JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true });

            return Task.FromResult(new TaskResult
            {
                TaskId = task.TaskId,
                Success = true,
                Output = json,
                StructuredData = info,
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

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static List<Dictionary<string, object?>> GetNetworkInfo()
    {
        var result = new List<Dictionary<string, object?>>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var props = ni.GetIPProperties();
                var ips = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .ToList();

                if (ips.Count == 0) continue;

                result.Add(new Dictionary<string, object?>
                {
                    ["name"] = ni.Name,
                    ["description"] = ni.Description,
                    ["type"] = ni.NetworkInterfaceType.ToString(),
                    ["mac"] = ni.GetPhysicalAddress().ToString(),
                    ["ipv4"] = ips,
                    ["dns_servers"] = props.DnsAddresses.Select(a => a.ToString()).ToList(),
                    ["gateway"] = props.GatewayAddresses.Select(a => a.Address.ToString()).ToList(),
                });
            }
        }
        catch { }
        return result;
    }

    private static Dictionary<string, string> GetEnvironmentVars()
    {
        var result = new Dictionary<string, string>();
        var interesting = new[]
        {
            "COMPUTERNAME", "USERDOMAIN", "USERDNSDOMAIN", "LOGONSERVER",
            "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR",
            "PROGRAMFILES", "PROGRAMFILES(X86)", "APPDATA", "LOCALAPPDATA",
            "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "PROCESSOR_IDENTIFIER",
        };

        foreach (var key in interesting)
        {
            var val = Environment.GetEnvironmentVariable(key);
            if (val != null)
                result[key] = val;
        }
        return result;
    }

    private static List<Dictionary<string, object?>> GetDriveInfo()
    {
        var result = new List<Dictionary<string, object?>>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                result.Add(new Dictionary<string, object?>
                {
                    ["name"] = drive.Name,
                    ["label"] = drive.VolumeLabel,
                    ["type"] = drive.DriveType.ToString(),
                    ["format"] = drive.DriveFormat,
                    ["total_gb"] = Math.Round(drive.TotalSize / 1073741824.0, 1),
                    ["free_gb"] = Math.Round(drive.AvailableFreeSpace / 1073741824.0, 1),
                });
            }
        }
        catch { }
        return result;
    }

    private static List<Dictionary<string, object?>> GetTopProcesses()
    {
        var result = new List<Dictionary<string, object?>>();
        try
        {
            var procs = Process.GetProcesses()
                .OrderByDescending(p =>
                {
                    try { return p.WorkingSet64; } catch { return 0; }
                })
                .Take(20);

            foreach (var p in procs)
            {
                try
                {
                    result.Add(new Dictionary<string, object?>
                    {
                        ["pid"] = p.Id,
                        ["name"] = p.ProcessName,
                        ["memory_mb"] = Math.Round(p.WorkingSet64 / 1048576.0, 1),
                    });
                }
                catch { }
            }
        }
        catch { }
        return result;
    }
}
