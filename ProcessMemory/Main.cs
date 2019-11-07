using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        if (GetExitCodeProcess(processHandle, out uint code) && code != 259) {
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

    public byte[] ReadByteArray(IntPtr addr, uint size) {
        if (!CheckProcess()) return new byte[0];

        uint flNewProtect;
        VirtualProtectEx(processHandle, addr, (UIntPtr)size, 0x04 /* rw */, out flNewProtect);

        byte[] array = new byte[size];
        ReadProcessMemory(processHandle, addr, array, size, 0u);

        VirtualProtectEx(processHandle, addr, (UIntPtr)size, flNewProtect, out flNewProtect);
        //CloseHandle(processHandle);
        return array;
    }

    public string ReadStringUnicode(IntPtr addr, uint size) => CheckProcess()
        ? Encoding.Unicode.GetString(ReadByteArray(addr, size), 0, (int)size)
        : "";
        
    public string ReadStringASCII(IntPtr addr, uint size) => CheckProcess()
        ? Encoding.ASCII.GetString(ReadByteArray(addr, size), 0, (int)size)
        : "";
        
    public char ReadChar(IntPtr addr) => CheckProcess()
        ? BitConverter.ToChar(ReadByteArray(addr, 1), 0)
        : ' ';
        
    public bool ReadBoolean(IntPtr addr) => CheckProcess()
        ? BitConverter.ToBoolean(ReadByteArray(addr, 1), 0)
        : false;

    public byte ReadByte(IntPtr addr) => CheckProcess()
        ? ReadByteArray(addr, 1)[0]
        : (byte)0;

    public short ReadInt16(IntPtr addr) => CheckProcess()
        ? BitConverter.ToInt16(ReadByteArray(addr, 2), 0)
        : (short)0;

    public int ReadInt32(IntPtr addr) => CheckProcess()
        ? BitConverter.ToInt32(ReadByteArray(addr, 4), 0)
        : 0;

    public long ReadInt64(IntPtr addr) => CheckProcess()
        ? BitConverter.ToInt64(ReadByteArray(addr, 8), 0)
        : 0;

    public ushort ReadUInt16(IntPtr addr) => CheckProcess()
        ? BitConverter.ToUInt16(ReadByteArray(addr, 2), 0)
        : (ushort)0;

    public uint ReadUInt32(IntPtr addr) => CheckProcess()
        ? BitConverter.ToUInt32(ReadByteArray(addr, 4), 0)
        : 0;

    public ulong ReadUInt64(IntPtr addr) => CheckProcess()
        ? BitConverter.ToUInt64(ReadByteArray(addr, 8), 0)
        : 0;
        
    public float ReadFloat(IntPtr addr) => CheckProcess()
        ? BitConverter.ToSingle(ReadByteArray(addr, 4), 0)
        : 0f;
        
    public double ReadDouble(IntPtr addr) => CheckProcess()
        ? BitConverter.ToDouble(ReadByteArray(addr, 8), 0)
        : 0.0;

    public bool WriteByteArray(IntPtr addr, byte[] pBytes) {
        if (!CheckProcess()) return false;

        uint flNewProtect;
        VirtualProtectEx(processHandle, addr, (UIntPtr)pBytes.Length, 0x04 /* rw */, out flNewProtect);

        bool flag = WriteProcessMemory(processHandle, addr, pBytes, (uint)pBytes.Length, 0u);

        VirtualProtectEx(processHandle, addr, (UIntPtr)pBytes.Length, flNewProtect, out flNewProtect);
        return flag;
    }

    public bool WriteStringUnicode(IntPtr addr, string pData) => WriteByteArray(addr, Encoding.Unicode.GetBytes(pData));

    public bool WriteStringASCII(IntPtr addr, string pData) => WriteByteArray(addr, Encoding.ASCII.GetBytes(pData));
        
    public bool WriteBoolean(IntPtr addr, bool pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteChar(IntPtr addr, char pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteByte(IntPtr addr, byte pData) => WriteByteArray(addr, new byte[] {pData});

    public bool WriteInt16(IntPtr addr, short pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteInt32(IntPtr addr, int pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteInt64(IntPtr addr, long pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteUInt16(IntPtr addr, ushort pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteUInt32(IntPtr addr, uint pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteUInt64(IntPtr addr, ulong pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteFloat(IntPtr addr, float pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool WriteDouble(IntPtr addr, double pData) => WriteByteArray(addr, BitConverter.GetBytes(pData));

    public bool Traverse(IntPtr addr, IEnumerable<int> offsets, out IntPtr result) {
        result = addr;

        if (!CheckProcess() || result == IntPtr.Zero) return false;

        foreach (int offset in offsets) {
            result = (IntPtr)ReadInt64(result);
            if (result == IntPtr.Zero) return false;

            result += offset;
        }

        return true;
    }

    public string TraverseStringUnicode(IntPtr addr, IEnumerable<int> offsets, uint size) => Traverse(addr, offsets, out IntPtr result)
        ? ReadStringUnicode(result, size)
        : null;

    public string TraverseStringASCII(IntPtr addr, IEnumerable<int> offsets, uint size) => Traverse(addr, offsets, out IntPtr result)
        ? ReadStringASCII(result, size)
        : null;

    public char? TraverseChar(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadChar(result)
        : (char?)null;

    public bool? TraverseBoolean(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadBoolean(result)
        : (bool?)null;

    public byte? TraverseByte(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadByte(result)
        : (byte?)null;

    public short? TraverseInt16(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadInt16(result)
        : (short?)null;

    public int? TraverseInt32(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadInt32(result)
        : (int?)null;

    public long? TraverseInt64(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadInt64(result)
        : (long?)null;

    public ushort? TraverseUInt16(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadUInt16(result)
        : (ushort?)null;

    public uint? TraverseUInt32(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadUInt32(result)
        : (uint?)null;

    public ulong? TraverseUInt64(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadUInt64(result)
        : (ulong?)null;

    public float? TraverseFloat(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadFloat(result)
        : (float?)null;

    public double? TraverseDouble(IntPtr addr, IEnumerable<int> offsets) => Traverse(addr, offsets, out IntPtr result)
        ? ReadDouble(result)
        : (double?)null;
}