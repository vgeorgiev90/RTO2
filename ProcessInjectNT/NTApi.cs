using System;
using System.Runtime.InteropServices;

namespace ProcessInjectNT
{
    internal class NTApi
    {

        [DllImport("ntdll.dll", EntryPoint = "#310", CharSet = CharSet.Unicode, SetLastError = true)]
        //NtCreateSection - out hSection, ulong desired_access, IntPtr object_attributes,
        //ulong max_size, ulong page_attributes, ulong section_attributes, IntPtr file_handle
        public static extern void NTS(
            ref IntPtr hSection, 
            ulong daccess, 
            IntPtr oattr, 
            ref ulong size, 
            ulong pattr, 
            ulong sattr, 
            IntPtr fhand
            );

        [DllImport("ntdll.dll", EntryPoint = "#413", CharSet = CharSet.Unicode, SetLastError = true)]
        //NtMapViewOfSection - SectionHandle, ProcHandle, *BaseAddress, ZeroBits, CommitSize, SectionOffset,
        //ViewSize, InheritDisposition, AllocationType, Protect
        public static extern void NMVS(
            IntPtr hSection,
            IntPtr phand,
            out IntPtr addr,
            IntPtr zbits,
            IntPtr csize,
            IntPtr soff,
            out ulong vsize,
            uint idisps,
            uint alloctype,
            uint protect
            );

        [DllImport("ntdll.dll", EntryPoint = "#315", CharSet = CharSet.Unicode, SetLastError = true)]
        //NtCreateThreadEx - out IntPtr hthread, ulong desired_access, IntPtr ObjectAttributes, 
        //IntPtr ProcessHandle, IntPtr RemoteBaseAddress, IntPtr lpParameter, bool CreateSuspended,
        //int StackZeroBits, int SizeOfStackCommit, int SizeOfStackReserve, IntPtr ThreadInfo
        public static extern void NCTE(
            out IntPtr hth,
            ulong daccess,
            IntPtr oattr,
            IntPtr phand,
            IntPtr remoteaddr,
            IntPtr lparam,
            bool suspend,
            int szbits,
            int sc_size,
            int sr_size,
            IntPtr tinfo
            );
    }
}
