using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessMemory.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Library.ProcessMemory processMemory = new Library.ProcessMemory("puyopuyotetris");

            string myName = processMemory.ReadStringUnicode(new IntPtr(0x14059B418), 36);

            while (true)
            {
                Console.Clear();
                Console.WriteLine($"Name : {myName}");
                Console.WriteLine($"Stars : {PlayerStar(0)} : {PlayerStar(1)}");
                Console.WriteLine($"Score : {PlayerScore(0)} : {PlayerScore(1)}");
                Thread.Sleep(30);
            }

            int PlayerStar(int index) => processMemory.ReadInt32(new IntPtr(0x14057F048), index * 0x04 + 0x38);
            int PlayerScore(int index)
            {
                switch (index)
                {
                    case 0: return processMemory.ReadInt32(new IntPtr(0x140461B28), 0x380, 0x18, 0xE0, 0x3C);
                    case 1: return processMemory.ReadInt32(new IntPtr(0x140460690), 0x2D0, 0x0, 0x38, 0x78, 0xE0, 0x3C);
                    default: return -1;
                }
            }
        }
    }
}
