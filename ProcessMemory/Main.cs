using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

public class ProcessMemory {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeProcess(IntPtr hObject, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject); // unused?

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); // unused?

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    private static extern int ResumeThread(IntPtr hThread);

    private IntPtr baseAddress;
    public long getBaseAddress {
        get {
            if (CheckProcess()) {
                baseAddress = (IntPtr)0;
                processModule = mainProcess[0].MainModule;
                baseAddress = processModule.BaseAddress;
                return (long)baseAddress;
            } else return 0;
        }
    }

    public string processName;
    public bool TrustProcess;
    private bool _opened;
    private ProcessModule processModule;
    private Process[] mainProcess;
    private IntPtr processHandle = IntPtr.Zero;

    public ProcessMemory(string param, bool trust = false) {
        processName = param;
        TrustProcess = trust;
    }

    public bool CheckProcess() {
        if (TrustProcess && _opened) return true;
        if (processName == null) return false;

        bool success = GetExitCodeProcess(processHandle, out uint code);

        if (success && code != 259) {
            CloseHandle(processHandle);
            processHandle = IntPtr.Zero;
        }

        if (processHandle == IntPtr.Zero) {
            mainProcess = Process.GetProcessesByName(processName);
            if (mainProcess.Length == 0) return false;

            processHandle = OpenProcess(0x001F0FFF, false, mainProcess[0].Id);
            if (processHandle == IntPtr.Zero) return false;
        }

        if (TrustProcess) _opened = true;
        return true;
    }

    public void Suspend() {
        foreach (ProcessThread pT in mainProcess[0].Threads) {
            IntPtr pOpenThread = OpenThread(0x02 /* suspend/resume */, false, (uint)pT.Id);

            if (pOpenThread == IntPtr.Zero) {
                continue;
            }

            SuspendThread(pOpenThread);

            CloseHandle(pOpenThread);
        }
    }

    public void Resume() {
        foreach (ProcessThread pT in mainProcess[0].Threads) {
            IntPtr pOpenThread = OpenThread(0x02 /* suspend/resume */, false, (uint)pT.Id);

            if (pOpenThread == IntPtr.Zero) {
                continue;
            }

            var suspendCount = 0;
            do {
                suspendCount = ResumeThread(pOpenThread);
            } while (suspendCount > 0);

            CloseHandle(pOpenThread);
        }
    }

    public byte[] ReadByteArray(IntPtr pOffset, uint pSize) {
        if (CheckProcess()) {
            uint flNewProtect;
            VirtualProtectEx(processHandle, pOffset, (UIntPtr)pSize, 0x04 /* rw */, out flNewProtect);

            byte[] array = new byte[pSize];
            ReadProcessMemory(processHandle, pOffset, array, pSize, 0u);

            VirtualProtectEx(processHandle, pOffset, (UIntPtr)pSize, flNewProtect, out flNewProtect);
            //CloseHandle(processHandle);
            return array;

        } else return new byte[1];
    }

    public bool WriteByteArray(IntPtr pOffset, byte[] pBytes) {
        if (CheckProcess()) {
            uint flNewProtect;
            VirtualProtectEx(processHandle, pOffset, (UIntPtr)pBytes.Length, 0x04 /* rw */, out flNewProtect);

            bool flag = WriteProcessMemory(processHandle, pOffset, pBytes, (uint)pBytes.Length, 0u);

            VirtualProtectEx(processHandle, pOffset, (UIntPtr)pBytes.Length, flNewProtect, out flNewProtect);
            return flag;

        } else return false;
    }

    public string ReadStringUnicode(IntPtr pOffset, uint pSize) => CheckProcess()
        ? Encoding.Unicode.GetString(ReadByteArray(pOffset, pSize), 0, (int)pSize)
        : "";
        
    public string ReadStringASCII(IntPtr pOffset, uint pSize) => CheckProcess()
        ? Encoding.ASCII.GetString(ReadByteArray(pOffset, pSize), 0, (int)pSize)
        : "";
        
    public char ReadChar(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToChar(ReadByteArray(pOffset, 0x01), 0)
        : ' ';
        
    public bool ReadBoolean(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToBoolean(ReadByteArray(pOffset, 0x01), 0)
        : false;

    public byte ReadByte(IntPtr pOffset) => CheckProcess()
        ? ReadByteArray(pOffset, 0x01)[0]
        : (byte)0;

    public short ReadInt16(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToInt16(ReadByteArray(pOffset, 0x02), 0)
        : (short)0;

    public int ReadInt32(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToInt32(ReadByteArray(pOffset, 4u), 0)
        : 0;

    public long ReadInt64(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToInt64(ReadByteArray(pOffset, 8u), 0)
        : 0;

    public ushort ReadUInt16(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt16(ReadByteArray(pOffset, 0x02), 0)
        : (ushort)0;

    public uint ReadUInt32(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt32(ReadByteArray(pOffset, 4u), 0)
        : 0;

    public ulong ReadUInt64(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt64(ReadByteArray(pOffset, 8u), 0)
        : 0;
        
    public float ReadFloat(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToSingle(ReadByteArray(pOffset, 8u), 0)
        : 0f;
        
    public double ReadDouble(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToDouble(ReadByteArray(pOffset, 8u), 0)
        : 0.0;
        
    public bool WriteStringUnicode(IntPtr pOffset, string pData) => WriteByteArray(pOffset, Encoding.Unicode.GetBytes(pData));

    public bool WriteStringASCII(IntPtr pOffset, string pData) => WriteByteArray(pOffset, Encoding.ASCII.GetBytes(pData));
        
    public bool WriteBoolean(IntPtr pOffset, bool pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteChar(IntPtr pOffset, char pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteByte(IntPtr pOffset, byte pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData).Take(1).ToArray());

    public bool WriteInt16(IntPtr pOffset, short pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteInt32(IntPtr pOffset, int pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteInt64(IntPtr pOffset, long pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteUInt16(IntPtr pOffset, ushort pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteUInt32(IntPtr pOffset, uint pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteUInt64(IntPtr pOffset, ulong pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteFloat(IntPtr pOffset, float pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteDouble(IntPtr pOffset, double pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));
}