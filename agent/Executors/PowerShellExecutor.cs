using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using OBAIAgent.Models;

namespace OBAIAgent.Executors;

public static class PowerShellExecutor
{
    public static async Task<TaskResult> ExecuteAsync(TaskMessage task, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        string command = task.Command;

        if (string.IsNullOrWhiteSpace(command))
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = "Empty command",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };

        try
        {
            using var ps = PowerShell.Create();

            var iss = InitialSessionState.CreateDefault2();
            using var runspace = RunspaceFactory.CreateRunspace(iss);
            runspace.Open();
            ps.Runspace = runspace;

            ps.AddScript(command);
            ps.AddCommand("Out-String").AddParameter("Width", 250);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(task.Timeout > 0 ? task.Timeout : 120));

            var outputTask = Task.Run(() => ps.Invoke(), timeoutCts.Token);

            var results = await outputTask;

            var output = new StringBuilder();
            foreach (var item in results)
            {
                if (item != null)
                    output.AppendLine(item.ToString());
            }

            if (ps.HadErrors)
            {
                var errors = new StringBuilder();
                foreach (var err in ps.Streams.Error)
                    errors.AppendLine(err.ToString());

                return new TaskResult
                {
                    TaskId = task.TaskId,
                    Success = true,
                    Output = output.ToString(),
                    Error = errors.ToString(),
                    ExecutionTimeMs = sw.ElapsedMilliseconds,
                };
            }

            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = true,
                Output = output.ToString(),
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = $"Command timed out after {task.Timeout}s",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
        catch (Exception ex)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = $"{ex.GetType().Name}: {ex.Message}",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
    }
}
