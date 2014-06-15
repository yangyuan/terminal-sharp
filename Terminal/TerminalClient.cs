using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
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
            size = (size + 16) / 16 * 16;

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

        public static byte[] MakePadding(byte[] data, int size)
        {
            int extra = data.Length % size;
            if (extra == 0)
            {
                return (byte[])data.Clone();
            }

            extra = size - extra;
            byte[] cache = new byte[data.Length + extra];
            Array.Copy(data, cache, data.Length);
            int padding = cache[4];
            padding += extra;
            cache[4] = (byte)padding;
            return cache;
        }

        public static byte[] ComputeMAC(byte[] key, uint seqo, byte[] data, HashAlgorithm hash)
        {
            MemoryStream ms_cache = new MemoryStream();
            NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
            nbw_cache.WriteUInt32(seqo);
            nbw_cache.WriteBytes(data);
            nbw_cache.Flush();
            byte[] xxx = ms_cache.ToArray();

            byte[] key_buffer = new byte[64];
            Array.Clear(key_buffer, 0, key_buffer.Length);
            Array.Copy(key, 0, key_buffer, 0, key.Length);

            byte[] padding1 = new byte[64];
            for (int i = 0; i < 64; i++)
                padding1[i] = (byte)(key_buffer[i] ^ 0x36);
            byte[] padding2 = new byte[64];
            for (int i = 0; i < 64; i++)
                padding2[i] = (byte)(key_buffer[i] ^ 0x5C);

            hash.Initialize();
            hash.TransformBlock(padding1, 0, padding1.Length, padding1, 0);
            hash.TransformFinalBlock(xxx, 0, xxx.Length);
            xxx = (byte[])hash.Hash.Clone();
            hash.Initialize();
            hash.TransformBlock(padding2, 0, padding2.Length, padding2, 0);
            hash.TransformFinalBlock(xxx, 0, xxx.Length);

            return hash.Hash;
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
