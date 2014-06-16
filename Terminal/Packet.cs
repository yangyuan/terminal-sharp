using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Terminal
{
    public class Packet
    {
        public const int SSH_MSG_KEXINIT = 20;
        public const int SSH_MSG_KEXDH_INIT = 30;
        public const int SSH_MSG_KEXDH_REPLY = 31;
        public const int SSH_MSG_USERAUTH_REQUEST = 5;
        public const int SSH_MSG_SERVICE_ACCEPT = 6;
        public const int SSH_MSG_USERAUTH_SUCCESS = 52;
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
        public PacketKeyExchange(Packet p)
            : base(p)
        {
        }
        override public void Parse()
        {
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
}
