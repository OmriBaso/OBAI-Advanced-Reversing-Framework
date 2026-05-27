using System.Diagnostics;
using OBAIAgent.Executors;
using OBAIAgent.Models;

namespace OBAIAgent;

public class TaskDispatcher
{
    public async Task<TaskResult> ExecuteAsync(TaskMessage task, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            return task.Type.ToLower() switch
            {
                "powershell" or "ps" => await PowerShellExecutor.ExecuteAsync(task, ct),
                "csharp" or "cs" => await CSharpExecutor.ExecuteAsync(task, ct),
                "system_info" or "sysinfo" => await SystemInfoCollector.ExecuteAsync(task, ct),
                "ad_query" or "ad" => await ADEnumerator.ExecuteAsync(task, ct),
                "ping" => Task.FromResult(new TaskResult
                {
                    TaskId = task.TaskId,
                    Success = true,
                    Output = "pong",
                    ExecutionTimeMs = sw.ElapsedMilliseconds,
                }).Result,
                _ => new TaskResult
                {
                    TaskId = task.TaskId,
                    Success = false,
                    Error = $"Unknown task type: {task.Type}",
                    ExecutionTimeMs = sw.ElapsedMilliseconds,
                },
            };
        }
        catch (OperationCanceledException)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = "Task cancelled",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
        catch (Exception ex)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = $"Dispatcher error: {ex.GetType().Name}: {ex.Message}",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
    }
}
