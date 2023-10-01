using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;

namespace ProcessHollow
{
    internal class Program
    { 
        public const uint WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
        public const uint WINHTTP_FLAG_ASYNC = 0x10000000;
        public static void Main(string[] args)
        {
            DLL wh = new DLL("winhttp.dll");
            var openConnWinHttp = wh.ChaseFunction("WinHttpOpen") as WinHttpOpen;
            var hConn = openConnWinHttp("useragent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, WINHTTP_FLAG_ASYNC);

            if (hConn == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open session. Error: " + Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine("Session opened successfully!");
            }

        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UInt32 lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr WinHttpOpen(string pszAgentW, uint dwAccessType, string pszProxyW, string pszProxyBypassW, uint dwFlags);

}
