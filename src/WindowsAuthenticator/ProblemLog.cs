using System.Globalization;
using Vault;

namespace WindowsAuthenticator;

/// <summary>The log of the Vault problems, a text file of the current user without secrets.</summary>
internal static class ProblemLog
{
    /// <summary>The log file, %LOCALAPPDATA%\pl.waw.koszewscy\WindowsAuthenticator\vault.log.</summary>
    public static string FilePath { get; } = Path.Combine(Settings.DataFolder, "vault.log");

    /// <summary>Appends a line naming the vault, the time and the problem; a log that cannot be written is skipped.</summary>
    public static void Write(string vault, VaultProblem problem)
    {
        var line = string.Create(CultureInfo.InvariantCulture,
                                 $"{DateTimeOffset.Now:yyyy-MM-dd'T'HH:mm:sszzz} {vault}: {problem.Title} - {problem.Detail}");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.AppendAllLines(FilePath, [line.ReplaceLineEndings(" ")]);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // The log is a convenience; the problem is shown in the app all the same.
        }
    }
}
