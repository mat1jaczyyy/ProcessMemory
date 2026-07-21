# ProcessMemory

ProcessMemory is a small Windows x64 library for reading, writing, allocating, and traversing memory in another process.

Version 1.3 targets .NET Framework 4.7.2. The public API remains compatible with ProcessMemory 1.2.1.

## Install

```powershell
dotnet add package ProcessMemory --version 1.3.0
```

The consuming application must run as x64 and may require elevated permissions to open its target process.

## Example

```csharp
var memory = new ProcessMemory("MyGame");

if (memory.CheckProcess()) {
    var baseAddress = new IntPtr(memory.getBaseAddress);
    var value = memory.ReadInt32(baseAddress + 0x1234);
    memory.WriteInt32(baseAddress + 0x1234, value + 1);
}
```
