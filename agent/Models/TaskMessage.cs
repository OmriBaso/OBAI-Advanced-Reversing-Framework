using System.Text.Json.Serialization;

namespace OBAIAgent.Models;

public class TaskMessage
{
    [JsonPropertyName("task_id")]
    public string TaskId { get; set; } = "";

    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; } = 120;

    [JsonPropertyName("parameters")]
    public Dictionary<string, string>? Parameters { get; set; }
}

public class TaskResult
{
    [JsonPropertyName("task_id")]
    public string TaskId { get; set; } = "";

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("output")]
    public string Output { get; set; } = "";

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("execution_time_ms")]
    public long ExecutionTimeMs { get; set; }

    [JsonPropertyName("structured_data")]
    public object? StructuredData { get; set; }
}

public class RegisterRequest
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = "";

    [JsonPropertyName("domain")]
    public string Domain { get; set; } = "";

    [JsonPropertyName("username")]
    public string Username { get; set; } = "";

    [JsonPropertyName("os_version")]
    public string OsVersion { get; set; } = "";

    [JsonPropertyName("ip_addresses")]
    public List<string> IpAddresses { get; set; } = new();

    [JsonPropertyName("is_elevated")]
    public bool IsElevated { get; set; }

    [JsonPropertyName("dotnet_version")]
    public string DotnetVersion { get; set; } = "";

    [JsonPropertyName("agent_version")]
    public string AgentVersion { get; set; } = "1.0.0";
}

public class RegisterResponse
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; set; } = "";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";
}

public class PollResponse
{
    [JsonPropertyName("has_task")]
    public bool HasTask { get; set; }

    [JsonPropertyName("task")]
    public TaskMessage? Task { get; set; }
}
