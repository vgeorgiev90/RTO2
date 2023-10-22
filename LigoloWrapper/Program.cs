using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace LigoloWrapper
{
    internal class Program
    {
        [DllImport("ligolo", EntryPoint = "main")]
        extern static void main();

        static void Main()
        {
            Console.WriteLine("Starting ligolo agent");
            main();
        }
    }
}
