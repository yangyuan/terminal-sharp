using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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
        byte[] verify_sig;

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

        // CryptoTransforms
        ICryptoTransform crypto_encryptor;
        ICryptoTransform crypto_decryptor;
        HashAlgorithm crypto_mac_decryptor;
        HashAlgorithm crypto_mac_encryptor;

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
            verify_sig = packet_dhkex_reply.GetSignature();
            BigInteger f = packet_dhkex_reply.GetExchangeValue();
            verify_f = f;
            BigInteger K = dh.ComputeKey(f);
            verify_k = K;
        }

        public void OpenChannel()
        {
            PacketGeneral packet_openchannel = new PacketGeneral(90);
            NetworkByteWriter nbw = packet_openchannel.GetStreamWriter();
            nbw.WriteString("session");
            nbw.WriteUInt32(0);
            nbw.WriteUInt32(1048576);
            nbw.WriteUInt32(16384);

            SendPacket(crypto_encryptor, packet_openchannel);

            Packet packet = RecvPacket(crypto_decryptor);
            NetworkByteReader nbr = packet.GenerateReader();

            nbr.ReadByte();
            uint recipient_channel = nbr.ReadUInt32();

            uint sender_channel = nbr.ReadUInt32();
            uint initial_window_size = nbr.ReadUInt32();
            uint maximum_packet_size = nbr.ReadUInt32();


            PacketGeneral packet_pty = new PacketGeneral(Packet.SSH_MSG_CHANNEL_REQUEST);
            nbw = packet_pty.GetStreamWriter();
            nbw.WriteUInt32(recipient_channel);
            nbw.WriteString("pty-req");
            nbw.WriteByte(0);
            nbw.WriteString("vt100");
            nbw.WriteUInt32(80);
            nbw.WriteUInt32(24);
            nbw.WriteUInt32(640);
            nbw.WriteUInt32(480);
            nbw.WriteString("");
            SendPacket(crypto_encryptor, packet_pty);

            PacketGeneral packet_shell = new PacketGeneral(Packet.SSH_MSG_CHANNEL_REQUEST);
            nbw = packet_shell.GetStreamWriter();
            nbw.WriteUInt32(recipient_channel);
            nbw.WriteString("shell");
            nbw.WriteByte(0);
            SendPacket(crypto_encryptor, packet_shell);

            

            while (true)
            {

                if (RecvAvailable())
                {
                    packet = RecvPacket(crypto_decryptor);
                    switch (packet.Message)
                    {
                        case Packet.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                            break;
                        case Packet.SSH_MSG_CHANNEL_DATA:
                            PacketChannelData p = new PacketChannelData(packet);
                            p.Parse();
                            break;
                        default:
                            break;
                    }
                }
                else
                {
                    if (Console.KeyAvailable)
                    {
                        string data = Console.ReadLine();
                        PacketGeneral packet_key = new PacketGeneral(Packet.SSH_MSG_CHANNEL_DATA);
                        nbw = packet_key.GetStreamWriter();
                        nbw.WriteUInt32(recipient_channel);
                        nbw.WriteString(data + "\n");
                        SendPacket(crypto_encryptor, packet_key);
                    }
                    Thread.Sleep(00);
                }
            }

            
        }

        public void DumpError(Packet packet)
        {
            MemoryStream ms = new MemoryStream(packet.GetPayload());
            NetworkByteReader nbr = new NetworkByteReader(ms);
            nbr.ReadByte();
            nbr.ReadUInt32();
            string xxx = nbr.ReadString();
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
                verify_h = hash.ComputeHash(cache.ToArray());

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
                    MemoryStream ms_tmp = new MemoryStream(verify_sig);
                    NetworkByteReader nbr_tmp = new NetworkByteReader(ms_tmp);

                    string type = nbr_tmp.ReadString();
                    rsa_signature_blob = nbr_tmp.ReadBlob();
                }


                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.ImportParameters(RSAKeyInfo);
                RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
                RSADeformatter.SetHashAlgorithm("SHA1");

                byte[] xx2 = SHA1.Create().ComputeHash(verify_h);
                bool verify = RSADeformatter.VerifySignature(xx2, rsa_signature_blob);
            }
        }

        public void KeyExchangeFinal()
        {
            Packet packet = RecvPacket(null);
            SendPacket(null, packet);
        }
        public void Authenticate()
        {
            PacketGeneral packet_auth = new PacketGeneral(Packet.SSH_MSG_USERAUTH_REQUEST);
            packet_auth.GetStreamWriter().WriteString("ssh-userauth");
            SendPacket(crypto_encryptor, packet_auth);
            Packet packet = RecvPacket(crypto_decryptor);
            if (packet.Message == Packet.SSH_MSG_SERVICE_ACCEPT)
            {
                Console.WriteLine("SSH_MSG_SERVICE_ACCEPT");
            }

            packet_auth = new PacketGeneral(50);
            NetworkByteWriter nbw_cache = packet_auth.GetStreamWriter();
            //SSH_MSG_USERAUTH_REQUEST
            nbw_cache.WriteString("root");
            nbw_cache.WriteString("ssh-connection");
            nbw_cache.WriteString("password");
            nbw_cache.WriteByte((byte)0);
            nbw_cache.WriteString("root");

            SendPacket(crypto_encryptor, packet_auth);

            packet = RecvPacket(crypto_decryptor);

            if (Packet.SSH_MSG_USERAUTH_SUCCESS == packet.Message)
            {
                Console.WriteLine("oh ya!");
            }
        }
        public void PrepareCryptoTransforms()
        {
            byte[] xxxxxxxxxx;
            HashAlgorithm hash_key = SHA1.Create();
            //
            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x41);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] IVc2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x42);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] IVs2c = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x43);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] Ec2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x44);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] Es2c = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x45);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] MACc2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(verify_k);
                nbw_cache.WriteBytes(verify_h);
                nbw_cache.WriteByte((byte)0x46);
                nbw_cache.WriteBytes(verify_h);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] MACs2c = hash_key.ComputeHash(xxxxxxxxxx);

            {
                byte[] tmp = new byte[16];
                Array.Copy(Ec2s, 0, tmp, 0, tmp.Length);
                Ec2s = tmp;
            }

            {
                byte[] tmp = new byte[16];
                Array.Copy(IVc2s, 0, tmp, 0, tmp.Length);
                IVc2s = tmp;
            }

            {
                byte[] tmp = new byte[16];
                Array.Copy(Es2c, 0, tmp, 0, tmp.Length);
                Es2c = tmp;
            }

            {
                byte[] tmp = new byte[16];
                Array.Copy(IVs2c, 0, tmp, 0, tmp.Length);
                IVs2c = tmp;
            }

            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.Mode = CipherMode.CBC;
            rijndael.Padding = PaddingMode.None;


            crypto_encryptor = rijndael.CreateEncryptor(Ec2s, IVc2s);
            crypto_decryptor = rijndael.CreateDecryptor(Es2c, IVs2c);

            crypto_mac_encryptor = HMACSHA1.Create();
            ((HMAC)crypto_mac_encryptor).Key = MACc2s;
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
                uint size = (uint)payload.Length;
                size += (5 + (uint)encryptor.InputBlockSize);
                size = (uint)((size + blocksize) / blocksize * blocksize);

                uint packet_length = size - 4;
                byte padding_length = (byte)(size - 5 - payload.Length);
                MemoryStream ms = new MemoryStream();
                NetworkByteWriter nbw = new NetworkByteWriter(ms);

                nbw.WriteUInt32(packet_length);
                nbw.WriteByte(padding_length);
                nbw.WriteBytes(payload);
                for (int i = 0; i < padding_length; i++) nbw.WriteByte(0x0C);
                nbw.Flush();

                // compute mac
                byte[] cache = ms.ToArray();
                
                MemoryStream ms_mac = new MemoryStream();
                NetworkByteWriter nbw_mac = new NetworkByteWriter(ms_mac);
                nbw_mac.WriteUInt32((uint)sequence);
                nbw_mac.WriteBytes(cache);
                nbw_mac.Flush();
                byte[] mac = crypto_mac_encryptor.ComputeHash(ms_mac.ToArray());





                crypto_encryptor.TransformBlock(cache, 0, cache.Length, cache, 0);

                writer.WriteBytes(cache);
                writer.Flush();
                if (crypto_mac_encryptor != null)
                {
                    writer.WriteBytes(mac);
                }
            }

            sequence++;


        }
        public bool RecvAvailable () {
            return tcpclient.Available != 0;
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
                    }
                    if (more <= 0) break;
                }

                byte[] mac = reader.ReadBytes(20);


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
        public static byte[] ComputeMAC(byte[] key, uint seqo, byte[] data, HashAlgorithm hash)
        {
            MemoryStream ms_cache = new MemoryStream();
            NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
            nbw_cache.WriteUInt32(seqo);
            nbw_cache.WriteBytes(data);
            nbw_cache.Flush();
            byte[] xxx = ms_cache.ToArray();

            HMAC hmac = HMACSHA1.Create();
            hmac.Key = key;

            return hmac.ComputeHash(xxx);
        }

    }

}
