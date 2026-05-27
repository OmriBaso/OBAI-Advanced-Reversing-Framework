using System.Diagnostics;
using System.Text;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using OBAIAgent.Models;

namespace OBAIAgent.Executors;

public static class CSharpExecutor
{
    private static readonly ScriptOptions DefaultOptions = ScriptOptions.Default
        .AddReferences(
            typeof(object).Assembly,
            typeof(Enumerable).Assembly,
            typeof(Console).Assembly,
            typeof(System.Net.Http.HttpClient).Assembly,
            typeof(System.IO.File).Assembly,
            typeof(System.Text.Json.JsonSerializer).Assembly,
            typeof(System.Net.NetworkInformation.NetworkInterface).Assembly
        )
        .AddImports(
            "System",
            "System.IO",
            "System.Linq",
            "System.Text",
            "System.Collections.Generic",
            "System.Net",
            "System.Net.Http",
            "System.Text.Json",
            "System.Threading.Tasks",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "System.Security.Principal",
            "Microsoft.Win32"
        );

    public static async Task<TaskResult> ExecuteAsync(TaskMessage task, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        string code = task.Command;

        if (string.IsNullOrWhiteSpace(code))
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Error = "Empty code",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };

        var capturedOutput = new StringBuilder();

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(task.Timeout > 0 ? task.Timeout : 120));

            var originalOut = Console.Out;
            using var writer = new StringWriter(capturedOutput);
            Console.SetOut(writer);

            try
            {
                var result = await CSharpScript.EvaluateAsync<object?>(
                    code,
                    DefaultOptions,
                    cancellationToken: timeoutCts.Token
                );

                Console.SetOut(originalOut);

                string output = capturedOutput.ToString();
                if (result != null)
                {
                    string resultStr = result.ToString() ?? "";
                    if (!string.IsNullOrEmpty(resultStr))
                        output = string.IsNullOrEmpty(output)
                            ? resultStr
                            : output + "\n" + resultStr;
                }

                return new TaskResult
                {
                    TaskId = task.TaskId,
                    Success = true,
                    Output = output,
                    ExecutionTimeMs = sw.ElapsedMilliseconds,
                };
            }
            finally
            {
                Console.SetOut(originalOut);
            }
        }
        catch (CompilationErrorException ex)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Output = capturedOutput.ToString(),
                Error = "Compilation errors:\n" + string.Join("\n", ex.Diagnostics),
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Output = capturedOutput.ToString(),
                Error = $"Code execution timed out after {task.Timeout}s",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
        catch (Exception ex)
        {
            return new TaskResult
            {
                TaskId = task.TaskId,
                Success = false,
                Output = capturedOutput.ToString(),
                Error = $"{ex.GetType().Name}: {ex.Message}",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
            };
        }
    }
}
