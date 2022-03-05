using System;
using System.Runtime.InteropServices;


public static class SandboxEvasion
{

    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);
    public static void sleep8sec_check()
    {
        DateTime t1 = DateTime.Now;
        Sleep(8000);
        double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
        if (t2 < 7.5)
        {
            System.Environment.Exit(0);
        }

    }
}
