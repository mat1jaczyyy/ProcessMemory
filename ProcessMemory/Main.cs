using System;
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

    private IntPtr baseAddress;
    public long getBaseAddress {
        get {
            baseAddress = (IntPtr)0;
            processModule = mainProcess[0].MainModule;
            baseAddress = processModule.BaseAddress;
            return (long)baseAddress;
        }
    }

    public string processName;
    private bool _trust;
    private ProcessModule processModule;
    private Process[] mainProcess;
    private IntPtr processHandle = IntPtr.Zero;

    public ProcessMemory(string param, bool trust = false) {
        processName = param;
        _trust = trust;
    }

    public bool CheckProcess() {
        if (_trust) return true;
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

        return true;
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

    public short ReadShort(IntPtr pOffset) => ReadInt16(pOffset);

    public int ReadInt32(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToInt32(ReadByteArray(pOffset, 4u), 0)
        : 0;
        
    public int ReadInteger(IntPtr pOffset) => ReadInt32(pOffset);

    public long ReadInt64(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToInt64(ReadByteArray(pOffset, 8u), 0)
        : 0;

    public long ReadLong(IntPtr pOffset) => ReadInt64(pOffset);

    public ushort ReadUInt16(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt16(ReadByteArray(pOffset, 0x02), 0)
        : (ushort)0;

    public ushort ReadUShort(IntPtr pOffset) => ReadUInt16(pOffset);

    public uint ReadUInt32(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt32(ReadByteArray(pOffset, 4u), 0)
        : 0;

    public uint ReadUInteger(IntPtr pOffset) => ReadUInt32(pOffset);

    public ulong ReadUInt64(IntPtr pOffset) => CheckProcess()
        ? BitConverter.ToUInt64(ReadByteArray(pOffset, 8u), 0)
        : 0;

    public ulong ReadULong(IntPtr pOffset) => ReadUInt64(pOffset);
        
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

    public bool WriteByte(IntPtr pOffset, byte pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteInt16(IntPtr pOffset, short pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteShort(IntPtr pOffset, short pData) => WriteInt16(pOffset, pData);

    public bool WriteInt32(IntPtr pOffset, int pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteInteger(IntPtr pOffset, int pData) => WriteInt32(pOffset, pData);

    public bool WriteInt64(IntPtr pOffset, long pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteLong(IntPtr pOffset, long pData) => WriteInt64(pOffset, pData);

    public bool WriteUInt16(IntPtr pOffset, ushort pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteUShort(IntPtr pOffset, ushort pData) => WriteUInt16(pOffset, pData);

    public bool WriteUInt32(IntPtr pOffset, uint pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteUInteger(IntPtr pOffset, uint pData) => WriteUInt32(pOffset, pData);

    public bool WriteUInt64(IntPtr pOffset, ulong pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteULong(IntPtr pOffset, ulong pData) => WriteUInt64(pOffset, pData);

    public bool WriteFloat(IntPtr pOffset, float pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));

    public bool WriteDouble(IntPtr pOffset, double pData) => WriteByteArray(pOffset, BitConverter.GetBytes(pData));
}