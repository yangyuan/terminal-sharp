using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;

namespace Terminal
{
    public class TerminalClient
    {
        public static string version = "SSH-2.0-TerminalSharp";
        public static byte[] CreatePackage(byte[] playload)
        {
            uint size = (uint)playload.Length;
            size += 5;
            size = (size + 16) / 8 * 8;

            uint packet_length = size - 4;
            byte padding_length = (byte)(size - 5 - playload.Length);

            byte[] result = new byte[size];
            byte[] padding = new byte[padding_length];

            MemoryStream ms = new MemoryStream(result);
            NetworkByteWriter nbw = new NetworkByteWriter(ms);

            nbw.WriteUInt32(packet_length);
            nbw.WriteByte(padding_length);
            nbw.WriteBytes(playload);
            nbw.WriteBytes(padding);
            nbw.Flush();
            return result;
        }

        public static byte[] ParsePackage(NetworkByteReader br)
        {
            uint packet_length = br.ReadUInt32();
            byte padding_length = br.ReadByte();
            byte[] payload = br.ReadBytes(packet_length - padding_length - 1);
            byte[] padding = br.ReadBytes(padding_length);
            return payload;
        }


    }



    public class NetworkByteWriter
    {
        BinaryWriter bw;
        public NetworkByteWriter(Stream input)
        {
            bw = new BinaryWriter(input);
        }

        public void WriteByte(Byte data)
        {
            bw.Write(data);
        }

        public void WriteBytes(Byte[] data)
        {
            bw.Write(data);
        }

        public void WriteBoolean(Boolean data)
        {
            bw.Write(data);
        }

        public void WriteUInt32(UInt32 data)
        {
            byte[] result = BitConverter.GetBytes(data);
            Array.Reverse(result);
            bw.Write(result);
        }
        public void WriteUInt64(UInt64 data)
        {
            byte[] result = BitConverter.GetBytes(data);
            Array.Reverse(result);
            bw.Write(result);
        }
        public void WriteString(String data)
        {
            byte[] result = Encoding.UTF8.GetBytes(data);
            WriteUInt32((UInt32)result.Length);
            bw.Write(result);
        }
        public void WriteBlob(Byte[] data)
        {
            WriteUInt32((UInt32)data.Length);
            bw.Write(data);
        }
        public void WriteNameList(String[] data)
        {
            String result = String.Join(",", data);
            WriteString(result);
        }
        public void WriteMPInt(BigInteger data)
        {
            byte[] result = data.ToByteArray();
            Array.Reverse(result);
            WriteUInt32((UInt32)result.Length);
            bw.Write(result);
        }
        public void Flush()
        {
            bw.Flush();
        }
    }

    public class NetworkByteReader
    {
        BinaryReader br;
        public NetworkByteReader(Stream input)
        {
            br = new BinaryReader(input);
        }

        public Byte ReadByte()
        {
            return br.ReadByte();
        }

        public Byte[] ReadBytes(UInt32 size)
        {
            return br.ReadBytes((int)size);
        }

        public Boolean ReadBoolean()
        {
            return br.ReadBoolean();
        }

        public UInt32 ReadUInt32()
        {
            byte[] result = br.ReadBytes(4);
            Array.Reverse(result);
            return BitConverter.ToUInt32(result, 0);
        }

        public UInt64 ReadUInt64()
        {
            byte[] result = br.ReadBytes(8);
            Array.Reverse(result);
            return BitConverter.ToUInt64(result, 0);
        }

        public BigInteger ReadMPInt()
        {
            uint size = ReadUInt32();
            byte[] data = br.ReadBytes((int)size);
            Array.Reverse(data);
            return new BigInteger(data);
        }

        public String ReadString()
        {
            uint size = ReadUInt32();
            byte[] result = br.ReadBytes((int)size);
            return Encoding.UTF8.GetString(result);
        }
        public Byte[] ReadBlob()
        {
            uint size = ReadUInt32();
            return br.ReadBytes((int)size);
        }
        public String[] ReadNameList()
        {
            uint size = ReadUInt32();
            byte[] result = br.ReadBytes((int)size);
            string list = Encoding.UTF8.GetString(result);
            char[] x = { ',' };
            return list.Split(x);
        }
    }
}
