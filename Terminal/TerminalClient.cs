using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Terminal
{
    public class TerminalClient
    {
        public const string version = "SSH-2.0-TerminalSharp";

        int sequence;
        public TerminalClient()
        {
            sequence = 0;
        }
        TcpClient tcpclient;
        NetworkByteReader reader;
        NetworkByteWriter writer;

        // verify
        string verify_v_c;
        string verify_v_s;
        byte[] verify_i_c;
        byte[] verify_i_s;
        byte[] verify_k_s;
        BigInteger verify_e;
        BigInteger verify_f;
        BigInteger verify_k;
        byte[] verify_h;

        // algorithms
        public string algorithm_kex;
        public string algorithm_server_host_key;
        string algorithm_encryption_client_to_server;
        string algorithm_encryption_server_to_client;
        string algorithm_mac_client_to_server;
        string algorithm_mac_server_to_client;
        string algorithm_compression_client_to_server;
        string algorithm_compression_server_to_client;
        string algorithm_languages_client_to_server;
        string algorithm_languages_server_to_client;

        public bool Connect(string address, int port) {
            tcpclient = new TcpClient(address, port);
            NetworkStream ns = tcpclient.GetStream();
            reader = new NetworkByteReader(ns);
            writer = new NetworkByteWriter(ns);
            return false;
        }
        public void VersionExchange()
        {
            // local stream reader writer
            StreamReader sr = new StreamReader(tcpclient.GetStream());
            StreamWriter wr = new StreamWriter(tcpclient.GetStream());

            // Version Exchange
            string version_server = sr.ReadLine();
            verify_v_s = version_server;
            Console.WriteLine("Server Version: " + version_server);
            wr.WriteLine(TerminalClient.version);
            verify_v_c = TerminalClient.version;
            wr.Flush();
            sequence++;
        }

        // KeyExchange is a multibyte packet based action
        public void KeyExchangeInit()
        {
            // This Should Be a KeyExchange Packet
            Packet packet = RecvPacket(null);
            PacketKeyExchange packet_kex_server = new PacketKeyExchange(packet);
            packet_kex_server.Parse();
            verify_i_s = packet_kex_server.GetPayload();
            PacketKeyExchange packet_kex_client = new PacketKeyExchange();
            packet_kex_client.Reset();
            packet_kex_client.Pack();
            verify_i_c = packet_kex_client.GetPayload();
            SendPacket(null, packet_kex_client);

            NegotiateAlgorithms(packet_kex_client, packet_kex_server);
        }
        public void KeyExchange(string algorithm)
        {
            DiffieHellman dh = new DiffieHellman(2);
            BigInteger e = dh.GenerateExchangeValue();
            verify_e = e;
            PacketGeneral packet_dhkex = new PacketGeneral(Packet.SSH_MSG_KEXDH_INIT);
            packet_dhkex.GetStreamWriter().WriteMPInt(e);
            SendPacket(null, packet_dhkex);

            Packet packet = RecvPacket(null);

            PacketKeyExchangeDHReply packet_dhkex_reply = new PacketKeyExchangeDHReply(packet);
            packet_dhkex_reply.Parse();
            verify_k_s = packet_dhkex_reply.GetCertificates();
            verify_h = packet_dhkex_reply.GetSignature();
            BigInteger f = packet_dhkex_reply.GetExchangeValue();
            verify_f = f;
            BigInteger K = dh.ComputeKey(f);
            verify_k = K;
        }
        public void KeyVerify(string algorithm, HashAlgorithm hash)
        {
            MemoryStream cache = new MemoryStream();
            NetworkByteWriter nbr_cache = new NetworkByteWriter(cache);

            nbr_cache.WriteString(verify_v_c);
            nbr_cache.WriteString(verify_v_s);
            nbr_cache.WriteBlob(verify_i_c);
            nbr_cache.WriteBlob(verify_i_s);
            nbr_cache.WriteBlob(verify_k_s);
            nbr_cache.WriteMPInt(verify_e);
            nbr_cache.WriteMPInt(verify_f);
            nbr_cache.WriteMPInt(verify_k);
            nbr_cache.Flush();

            if (algorithm == "ssh-rsa")
            {
                byte[] HEX_H = hash.ComputeHash(cache.ToArray());

                RSAParameters RSAKeyInfo = new RSAParameters();
                {
                    MemoryStream ms_tmp = new MemoryStream(verify_k_s);
                    NetworkByteReader nbr_tmp = new NetworkByteReader(ms_tmp);

                    string type = nbr_tmp.ReadString();
                    BigInteger rsa_e = nbr_tmp.ReadMPInt();
                    BigInteger rsa_n = nbr_tmp.ReadMPInt();
                    RSAKeyInfo.Modulus = NetworkByteUtils.BigIntegerToUnsignedArray(rsa_n);
                    RSAKeyInfo.Exponent = NetworkByteUtils.BigIntegerToUnsignedArray(rsa_e);
                }
                byte[] rsa_signature_blob;
                {
                    MemoryStream ms_tmp = new MemoryStream(verify_h);
                    NetworkByteReader nbr_tmp = new NetworkByteReader(ms_tmp);

                    string type = nbr_tmp.ReadString();
                    rsa_signature_blob = nbr_tmp.ReadBlob();
                }


                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.ImportParameters(RSAKeyInfo);
                RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
                RSADeformatter.SetHashAlgorithm("SHA1");

                byte[] xx2 = SHA1.Create().ComputeHash(HEX_H);
                bool verify = RSADeformatter.VerifySignature(xx2, rsa_signature_blob);
            }
        }
        private string NegotiateAlgorithm(string[] client, string[] server)
        {
            foreach (string c in client)
            {
                foreach (string s in server)
                {
                    if (c.CompareTo(s) == 0) return c;
                }
            }
            return null;
        }
        public bool NegotiateAlgorithms(PacketKeyExchange client, PacketKeyExchange server)
        {
            algorithm_kex = NegotiateAlgorithm(client.kex_algorithms, server.kex_algorithms);
            algorithm_server_host_key = NegotiateAlgorithm(client.server_host_key_algorithms, server.server_host_key_algorithms);
            algorithm_encryption_client_to_server = NegotiateAlgorithm(client.encryption_algorithms_client_to_server, server.encryption_algorithms_client_to_server);
            algorithm_encryption_server_to_client = NegotiateAlgorithm(client.encryption_algorithms_server_to_client, server.encryption_algorithms_server_to_client);
            algorithm_mac_client_to_server = NegotiateAlgorithm(client.mac_algorithms_client_to_server, server.mac_algorithms_client_to_server);
            algorithm_mac_server_to_client = NegotiateAlgorithm(client.mac_algorithms_server_to_client, server.mac_algorithms_server_to_client);
            algorithm_compression_client_to_server = NegotiateAlgorithm(client.compression_algorithms_client_to_server, server.compression_algorithms_client_to_server);
            algorithm_compression_server_to_client = NegotiateAlgorithm(client.compression_algorithms_server_to_client, server.compression_algorithms_server_to_client);
            algorithm_languages_client_to_server = NegotiateAlgorithm(client.languages_client_to_server, server.languages_client_to_server);
            algorithm_languages_server_to_client = NegotiateAlgorithm(client.languages_server_to_client, server.languages_server_to_client);

            if (algorithm_kex != null &&
                algorithm_server_host_key != null &&
                algorithm_encryption_client_to_server != null &&
                algorithm_encryption_server_to_client != null &&
                algorithm_mac_client_to_server != null &&
                algorithm_mac_server_to_client != null &&
                algorithm_compression_client_to_server != null &&
                algorithm_compression_server_to_client != null
                )
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public void SendPacket(ICryptoTransform encryptor, Packet packet)
        {
            byte[] payload = packet.GetPayload();
            int blocksize = 16;
            if (encryptor == null)
            {
                uint size = (uint)payload.Length;
                size += 5;
                size = (uint)((size + blocksize) / blocksize * blocksize);

                uint packet_length = size - 4;
                byte padding_length = (byte)(size - 5 - payload.Length);

                MemoryStream ms = new MemoryStream();
                NetworkByteWriter nbw = new NetworkByteWriter(ms);

                nbw.WriteUInt32(packet_length);
                nbw.WriteByte(padding_length);
                nbw.WriteBytes(payload);
                for (int i = 0; i < padding_length; i++ ) nbw.WriteByte(0x0C);
                nbw.Flush();

                writer.WriteBytes(ms.ToArray());
                writer.Flush();
            }
            else
            {
                blocksize = Math.Max(encryptor.InputBlockSize, blocksize);
            }
        }

        public Packet RecvPacket(ICryptoTransform decryptor)
        {
            if (decryptor == null)
            {
                Packet packet = new Packet();
                uint packet_length = reader.ReadUInt32();
                byte padding_length = reader.ReadByte();
                byte[] payload = reader.ReadBytes(packet_length - padding_length - 1);
                byte[] padding = reader.ReadBytes(padding_length);
                packet.SetPayload(payload);
                return packet;
            }
            else
            {
                int blocksize = Math.Max(decryptor.InputBlockSize, 8);
                MemoryStream ms_packet = new MemoryStream();
                NetworkByteWriter writer_packet = new NetworkByteWriter(ms_packet);

                byte[] buffer = new byte[blocksize];

                bool first = true;
                int more = 0;
                while (true)
                {
                    // read a block
                    int ret = reader.ReadBytes(buffer, 0, blocksize);
                    // must be a real block size;
                    if (ret != blocksize) return null;
                    decryptor.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
                    writer_packet.WriteBytes(buffer);

                    if (first) // it's first time, need parse packet_length and padding_length
                    {
                        NetworkByteReader reader_buffer = new NetworkByteReader(new MemoryStream(buffer));
                        uint packet_length_t = reader_buffer.ReadUInt32();
                        first = false;

                        more = (int)packet_length_t + 4 - blocksize;
                        if (more % blocksize != 0) return null;
                    }
                    else
                    {
                        more -= blocksize;
                        if (more <= 0) break;
                    }
                }

                ms_packet.Seek(0, SeekOrigin.Begin);
                NetworkByteReader reader_packet = new NetworkByteReader(ms_packet);

                Packet packet = new Packet();
                uint packet_length = reader_packet.ReadUInt32();
                byte padding_length = reader_packet.ReadByte();
                byte[] payload = reader_packet.ReadBytes(packet_length - padding_length - 1);
                byte[] padding = reader_packet.ReadBytes(padding_length);
                packet.SetPayload(payload);
                return packet;
            }
        }

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

    public class Packet
    {
        public const int SSH_MSG_KEXINIT = 20;
        public const int SSH_MSG_KEXDH_INIT = 30;
        public const int SSH_MSG_KEXDH_REPLY = 31;
        public int Message { get; protected set; }
        protected byte[] payload;
        public Packet()
        {
        }
        public Packet(Packet p)
        {
            SetPayload(p.GetPayload());
        }

        public void SetPayload(byte[] data)
        {
            this.payload = (byte[])data.Clone();
            Message = (int)data[0];
        }
        public byte[] GetPayload()
        {
            if (payload == null) Pack();
            return (byte[])payload.Clone();
        }

        virtual public void Parse()
        {
        }
        virtual public void Pack()
        {
        }
    }

    public class PacketGeneral : Packet
    {
        MemoryStream cache;
        NetworkByteWriter writer;
        public PacketGeneral(int message)
            : base()
        {
            cache = new MemoryStream();
            writer = new NetworkByteWriter(cache);
            writer.WriteByte((byte)message);
        }
        public NetworkByteWriter GetStreamWriter()
        {
            return writer;
        }
        override public void Pack()
        {
            writer.Flush();
            SetPayload(cache.ToArray());
        }
    }
    public class PacketKeyExchangeDHReply : Packet
    {
        byte[] certificates;
        byte[] signature;
        BigInteger f;
        public PacketKeyExchangeDHReply(Packet p)
            : base(p)
        {
        }
        override public void Parse()
        {
            MemoryStream ms = new MemoryStream(payload);
            NetworkByteReader nbr = new NetworkByteReader(ms);
            nbr.ReadByte();
            certificates = nbr.ReadBlob();

            {
                MemoryStream ms_tmp = new MemoryStream(certificates);
                NetworkByteReader nbr_tmp = new NetworkByteReader(ms_tmp);

                string type = nbr_tmp.ReadString();
                BigInteger rsa_e = nbr_tmp.ReadMPInt();
                BigInteger rsa_n = nbr_tmp.ReadMPInt();
            }

            f = nbr.ReadMPInt();
            signature = nbr.ReadBlob();
            {
                MemoryStream ms_tmp = new MemoryStream(signature);
                NetworkByteReader nbr_tmp = new NetworkByteReader(ms_tmp);

                string type = nbr_tmp.ReadString();
                byte[] rsa_signature_blob = nbr_tmp.ReadBlob();
            }
        }

        public BigInteger GetExchangeValue()
        {
            return f;
        }

        public byte[] GetCertificates()
        {
            return (byte[])certificates.Clone();
        }
        public byte[] GetSignature()
        {
            return (byte[])signature.Clone();
        }
    }
    public class PacketKeyExchange : Packet
    {
        public byte[] cookie;
        public string[] kex_algorithms;
        public string[] server_host_key_algorithms;
        public string[] encryption_algorithms_client_to_server;
        public string[] encryption_algorithms_server_to_client;
        public string[] mac_algorithms_client_to_server;
        public string[] mac_algorithms_server_to_client;
        public string[] compression_algorithms_client_to_server;
        public string[] compression_algorithms_server_to_client;
        public string[] languages_client_to_server;
        public string[] languages_server_to_client;
        public bool first_kex_packet_follows;
        public uint reserved;
        public PacketKeyExchange()
            : base()
        {
        }
        public PacketKeyExchange(Packet p):base(p)
        {
        }
        override public void Parse() {
            MemoryStream ms = new MemoryStream(payload);
            NetworkByteReader nbr = new NetworkByteReader(ms);
            nbr.ReadByte();
            cookie = nbr.ReadBytes(16);
            kex_algorithms = nbr.ReadNameList();
            server_host_key_algorithms = nbr.ReadNameList();
            encryption_algorithms_client_to_server = nbr.ReadNameList();
            encryption_algorithms_server_to_client = nbr.ReadNameList();
            mac_algorithms_client_to_server = nbr.ReadNameList();
            mac_algorithms_server_to_client = nbr.ReadNameList();
            compression_algorithms_client_to_server = nbr.ReadNameList();
            compression_algorithms_server_to_client = nbr.ReadNameList();
            languages_client_to_server = nbr.ReadNameList();
            languages_server_to_client = nbr.ReadNameList();
            first_kex_packet_follows = nbr.ReadBoolean();
            reserved = nbr.ReadUInt32();
        }
        override public void Pack()
        {
            MemoryStream ms = new MemoryStream();
            NetworkByteWriter nbw = new NetworkByteWriter(ms);

            nbw.WriteByte((byte)Message);
            nbw.WriteBytes(cookie);
            nbw.WriteNameList(kex_algorithms);
            nbw.WriteNameList(server_host_key_algorithms);
            nbw.WriteNameList(encryption_algorithms_client_to_server);
            nbw.WriteNameList(encryption_algorithms_server_to_client);
            nbw.WriteNameList(mac_algorithms_client_to_server);
            nbw.WriteNameList(mac_algorithms_server_to_client);
            nbw.WriteNameList(compression_algorithms_client_to_server);
            nbw.WriteNameList(compression_algorithms_server_to_client);
            nbw.WriteNameList(languages_client_to_server);
            nbw.WriteNameList(languages_server_to_client);
            nbw.WriteBoolean(first_kex_packet_follows);
            nbw.WriteUInt32(0);
            nbw.Flush();
            SetPayload(ms.ToArray());
        }
        public void Reset()
        {
            Message = (byte)SSH_MSG_KEXINIT;
            cookie = new byte[16];
            kex_algorithms = new string[] { "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1" };
            server_host_key_algorithms = new string[] { "ssh-rsa", "ssh-dss" };
            encryption_algorithms_client_to_server = new string[] { "aes128-cbc", "3des-cbc" };
            encryption_algorithms_server_to_client = new string[] { "aes128-cbc", "3des-cbc" };
            mac_algorithms_client_to_server = new string[] { "hmac-sha1", "hmac-sha1-96" };
            mac_algorithms_server_to_client = new string[] { "hmac-sha1", "hmac-sha1-96" };
            compression_algorithms_client_to_server = new string[] { "none" };
            compression_algorithms_server_to_client = new string[] { "none" };
            languages_client_to_server = new string[] { };
            languages_server_to_client = new string[] { };
            first_kex_packet_follows = false;
            reserved = 0;
        }
    }
    class NetworkByteUtils
    {
        public static byte[] BigIntegerToUnsignedArray(BigInteger value)
        {
            // assume the value is positive
            byte[] data = value.ToByteArray();
            Array.Reverse(data);
            if (data.Length == 1 || data[0] != 0)
            {
                return data;
            }
            else
            {
                byte[] cache = new byte[data.Length-1];
                Array.Copy(data, 1, cache, 0, data.Length - 1);
                return cache;
            }
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
        public void WriteBytes(Byte[] data, int index, int count)
        {
            bw.Write(data, index, count);
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
        public int ReadBytes(byte[] buffer, int index, int count)
        {
            return br.Read(buffer, index, count);
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
