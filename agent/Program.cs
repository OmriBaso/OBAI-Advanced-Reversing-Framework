using OBAIAgent;

namespace OBAIAgent;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ╔═══════════════════════════════════╗
  ║   OBAI Remote Investigation Agent ║
  ╚═══════════════════════════════════╝
");
        Console.ResetColor();

        if (args.Length < 1)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Usage: OBAIAgent.exe <backend-address> [--insecure]");
            Console.WriteLine("  Example: OBAIAgent.exe 192.168.1.25:8080");
            Console.WriteLine("  Example: OBAIAgent.exe https://obai.lab.local:8080");
            Console.ResetColor();
            return 1;
        }

        string raw = args[0];
        if (!raw.StartsWith("http://") && !raw.StartsWith("https://"))
            raw = "http://" + raw;

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var backendUri))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Invalid address: {args[0]}");
            Console.ResetColor();
            return 1;
        }

        string baseUrl = backendUri.ToString().TrimEnd('/');

        Console.WriteLine($"  Backend : {baseUrl}");
        Console.WriteLine($"  Host    : {Environment.MachineName}");
        Console.WriteLine($"  User    : {Environment.UserDomainName}\\{Environment.UserName}");
        Console.WriteLine();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\n[*] Shutting down...");
        };

        var client = new AgentClient(baseUrl);
        var dispatcher = new TaskDispatcher();

        try
        {
            Log("Registering with backend...", ConsoleColor.Yellow);
            string agentId = await client.RegisterAsync(cts.Token);
            Log($"Registered as agent {agentId}", ConsoleColor.Green);
            Log("Polling for tasks... (Ctrl+C to quit)\n", ConsoleColor.Gray);

            await RunLoop(client, dispatcher, agentId, cts.Token);
        }
        catch (OperationCanceledException)
        {
            Log("Agent stopped.", ConsoleColor.Yellow);
        }
        catch (Exception ex)
        {
            Log($"Fatal error: {ex.Message}", ConsoleColor.Red);
            return 1;
        }

        return 0;
    }

    static async Task RunLoop(AgentClient client, TaskDispatcher dispatcher, string agentId, CancellationToken ct)
    {
        int heartbeatCounter = 0;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var task = await client.PollAsync(agentId, ct);

                if (task == null)
                {
                    heartbeatCounter++;
                    if (heartbeatCounter >= 4) // heartbeat every ~2 minutes (4 x 30s polls)
                    {
                        await client.HeartbeatAsync(agentId, ct);
                        heartbeatCounter = 0;
                    }
                    continue;
                }

                heartbeatCounter = 0;
                Log($"Task [{task.TaskId}] type={task.Type}", ConsoleColor.Cyan);

                var result = await dispatcher.ExecuteAsync(task, ct);

                if (result.Success)
                    Log($"Task [{task.TaskId}] completed in {result.ExecutionTimeMs}ms", ConsoleColor.Green);
                else
                    Log($"Task [{task.TaskId}] failed: {result.Error}", ConsoleColor.Red);

                await client.PostResultAsync(agentId, result, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (HttpRequestException ex)
            {
                Log($"Connection error: {ex.Message} — retrying in 5s", ConsoleColor.Red);
                await Task.Delay(5000, ct);
            }
            catch (Exception ex)
            {
                Log($"Loop error: {ex.Message}", ConsoleColor.Red);
                await Task.Delay(2000, ct);
            }
        }
    }

    public static void Log(string msg, ConsoleColor color = ConsoleColor.Gray)
    {
        var ts = DateTime.Now.ToString("HH:mm:ss");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"[{ts}] ");
        Console.ForegroundColor = color;
        Console.WriteLine(msg);
        Console.ResetColor();
    }
}
