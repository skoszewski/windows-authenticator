using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Vault;

/// <summary>What the identity provider sent to the redirect URI.</summary>
/// <param name="Error">The provider's <c>error_description</c>, or its <c>error</c>, when the login was refused.</param>
public sealed record OidcCallback(string? State, string? Code, string? Error);

/// <summary>
/// A listener on the loopback interface, IPv4 and IPv6, that receives the browser's redirect of an OIDC login.
/// </summary>
public sealed class OidcCallbackListener : IDisposable
{
    public const string CallbackPath = "/oidc/callback";
    private const int MaxRequestLength = 16384;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    private readonly List<TcpListener> listeners = [];
    private readonly int port;

    public OidcCallbackListener(int port)
    {
        if (port is < 1 or > 65535)
        {
            throw VaultException.Oidc($"{port} is not a port number.");
        }
        this.port = port;
    }

    /// <summary>
    /// Starts listening on 127.0.0.1 and, where the system has IPv6, on ::1; a port in use fails with a
    /// <see cref="SocketException"/> of <see cref="SocketError.AddressAlreadyInUse"/>.
    /// </summary>
    public void Start()
    {
        var ipv4 = new TcpListener(IPAddress.Loopback, port);
        ipv4.Start();
        listeners.Add(ipv4);
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }
        var ipv6 = new TcpListener(IPAddress.IPv6Loopback, port);
        try
        {
            ipv6.Start();
            listeners.Add(ipv6);
        }
        catch (SocketException error) when (error.SocketErrorCode != SocketError.AddressAlreadyInUse)
        {
            ipv6.Dispose();
        }
        catch
        {
            ipv6.Dispose();
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Waits for the redirect, answering every other request with 404; fails when the timeout passes and stops
    /// when the token is cancelled. Each connection is served on its own, so a connection a browser opens in
    /// advance and sends nothing on does not hold up the one that brings the redirect.
    /// </summary>
    public async Task<OidcCallback> CallbackAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout ?? DefaultTimeout);
        var found = new TaskCompletionSource<OidcCallback>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreach (var listener in listeners)
        {
            _ = AcceptAsync(listener, found, deadline.Token);
        }
        try
        {
            return await found.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw VaultException.Oidc("The browser did not return in time.");
        }
        finally
        {
            await deadline.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Accepts the connections of the listener until the token is cancelled, serving each on its own.</summary>
    private static async Task AcceptAsync(TcpListener listener, TaskCompletionSource<OidcCallback> found,
                                          CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                _ = ServeAsync(client, found, cancellationToken);
            }
        }
        catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException or SocketException)
        {
            // The wait ended, or the listener was stopped.
        }
    }

    /// <summary>
    /// Answers one connection and reports the redirect; a connection that sends no request line within
    /// <see cref="RequestTimeout"/>, or breaks off, is closed.
    /// </summary>
    private static async Task ServeAsync(TcpClient client, TaskCompletionSource<OidcCallback> found,
                                         CancellationToken cancellationToken)
    {
        using (client)
        using (var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            idle.CancelAfter(RequestTimeout);
            try
            {
                if (await AnswerAsync(client, idle.Token).ConfigureAwait(false) is { } callback)
                {
                    found.TrySetResult(callback);
                }
            }
            catch (Exception error) when (error is IOException or SocketException or OperationCanceledException)
            {
                // A connection that is idle or broke off is not the redirect.
            }
        }
    }

    /// <summary>Reads the request of a connection and answers it; the callback, when it is the redirect.</summary>
    private static async Task<OidcCallback?> AnswerAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var stream = client.GetStream();
        var buffer = new byte[MaxRequestLength];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            length += read;
            if (buffer.AsSpan(0, length).IndexOf("\r\n"u8) >= 0)
            {
                break;
            }
        }
        var callback = Parse(Encoding.UTF8.GetString(buffer, 0, length));
        var status = callback is null ? "404 Not Found" : "200 OK";
        var page = callback is null
            ? "Not found."
            : "Signed in. You can close this tab and return to Windows Authenticator.";
        var body = $"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Windows Authenticator</title></head><body><p>{page}</p></body></html>";
        var response = $"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
                       + $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
        await stream.WriteAsync(Encoding.UTF8.GetBytes(response), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return callback;
    }

    /// <summary>The callback in the request line of an HTTP request, or null for any other request.</summary>
    public static OidcCallback? Parse(string request)
    {
        var line = request.Split("\r\n", 2)[0];
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || parts[0] != "GET")
        {
            return null;
        }
        var target = parts[1].Split('?', 2);
        if (target[0] != CallbackPath)
        {
            return null;
        }
        var values = new Dictionary<string, string>();
        if (target.Length == 2)
        {
            foreach (var item in target[1].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var pair = item.Split('=', 2);
                values[Uri.UnescapeDataString(pair[0])] = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
            }
        }
        return new OidcCallback(values.GetValueOrDefault("state"), values.GetValueOrDefault("code"),
                                values.GetValueOrDefault("error_description") ?? values.GetValueOrDefault("error"));
    }

    public void Dispose()
    {
        foreach (var listener in listeners)
        {
            listener.Dispose();
        }
        listeners.Clear();
    }
}
