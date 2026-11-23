using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace WindowsAuthenticator;

/// <summary>The Win32 functions of Credential Manager (wincred.h) and the icon and window helpers of user32.</summary>
internal static unsafe partial class NativeMethods
{
    public const uint CredTypeGeneric = 1;
    public const uint CredPersistLocalMachine = 2;
    public const int ErrorNotFound = 1168;
    public const int WsExNoActivate = 0x0800_0000;

    /// <summary>CREDENTIALW.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Credential
    {
        public uint Flags;
        public uint Type;
        public char* TargetName;
        public char* Comment;
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public byte* CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public CredentialAttribute* Attributes;
        public char* TargetAlias;
        public char* UserName;
    }

    /// <summary>CREDENTIAL_ATTRIBUTEW.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CredentialAttribute
    {
        public char* Keyword;
        public uint Flags;
        public uint ValueSize;
        public byte* Value;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredEnumerate(string? filter, uint flags, out uint count, out Credential** credentials);

    [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredRead(string targetName, uint type, uint flags, out Credential* credential);

    [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredWrite(Credential* credential, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CredDelete(string targetName, uint type, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
    public static partial void CredFree(void* buffer);

    [LibraryImport("user32.dll", EntryPoint = "DestroyIcon", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DestroyIcon(IntPtr icon);
}
