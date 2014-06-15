using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Terminal;

namespace TerminalConsole
{
    class Program
    {
        static void Debug()
        {
            /*
            HashAlgorithm hash = MD5.Create();
            MemoryStream ms_cache = new MemoryStream();
            NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
            byte[] x = new byte[] {
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
            };
            nbw_cache.WriteBytes(x);
            nbw_cache.WriteBytes(Encoding.ASCII.GetBytes("Hi There"));
            nbw_cache.Flush();

             hash.ComputeHash(ms_cache.ToArray());
             * */
        }
        static void Main(string[] args)
        {
            // learn and test
            Debug();

            TcpClient tc = new TcpClient("192.168.192.132", 22);
            NetworkStream ns = tc.GetStream();
            NetworkByteReader nbr = new NetworkByteReader(ns);
            NetworkByteWriter nbw = new NetworkByteWriter(ns);
            StreamReader sr = new StreamReader(ns);
            StreamWriter wr = new StreamWriter(ns);

            // Version Exchange
            string version = sr.ReadLine();
            Console.WriteLine("Server Version: " + version);
            wr.WriteLine(TerminalClient.version);
            wr.Flush();

            // Key Exchange
            byte[] kex = TerminalClient.ParsePackage(nbr);
            PackageKEXINIT pkex = new PackageKEXINIT();
            pkex.Load(kex);

            PackageKEXINIT pkex_client = new PackageKEXINIT();
            pkex_client.cookie = pkex.cookie;
            pkex_client.ReSet();

            byte[] kexs = TerminalClient.CreatePackage(pkex_client.Pack());
            nbw.WriteBytes(kexs);
            nbw.Flush();

            ExchangeMethods ems = PackageKEXINIT.Negotiate(pkex_client, pkex);
            BigInteger xxxxxxxxxxxe = DiffieHellmanX.CreateE();
            {

                MemoryStream ms = new MemoryStream();
                NetworkByteWriter nbw2 = new NetworkByteWriter(ms);
                nbw2.WriteByte(30); // SSH_MSG_KEXDH_INIT
                nbw2.WriteMPInt(xxxxxxxxxxxe);
                nbw2.Flush();

                byte[] data = ms.ToArray();

                byte[] packt2 = TerminalClient.CreatePackage(data);
                nbw.WriteBytes(packt2);
                nbw.Flush();
            }


            byte[] kex2 = TerminalClient.ParsePackage(nbr);

            BigInteger KEX_K = new BigInteger(0);
            byte[] HEX_H;

            {
                MemoryStream ms = new MemoryStream(kex2);
                NetworkByteReader nbr2 = new NetworkByteReader(ms);
                nbr2.ReadByte();
                byte[] certificates = nbr2.ReadBlob();
                MemoryStream ms3 = new MemoryStream(certificates);
                NetworkByteReader nbr3 = new NetworkByteReader(ms3);

                string id = nbr3.ReadString();
                BigInteger rsa_e = nbr3.ReadMPInt();
                BigInteger rsa_n = nbr3.ReadMPInt();

                BigInteger f = nbr2.ReadMPInt();
                byte[] signature = nbr2.ReadBlob();

                MemoryStream ms4 = new MemoryStream(signature);
                NetworkByteReader nbr4 = new NetworkByteReader(ms4);

                string id2 = nbr4.ReadString();
                byte[] rsa_signature_blob = nbr4.ReadBlob();


                //SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
                RSAParameters RSAKeyInfo = new RSAParameters();

                byte[] b_n = rsa_n.ToByteArray();
                byte[] b_e = rsa_e.ToByteArray();
                byte[] b_n2 = new byte[256];
                Array.Copy(b_n, b_n2, 256);
                Array.Reverse(b_n2);
                Array.Reverse(b_e);



                MemoryStream ms5 = new MemoryStream();
                NetworkByteWriter nbw5 = new NetworkByteWriter(ms5);

                string V_C = TerminalClient.version;
                string V_S = version;
                byte[] K_S = certificates;
                byte[] I_C = pkex_client.Pack();
                byte[] I_S = kex;
                BigInteger HHH_e = xxxxxxxxxxxe;
                BigInteger HHH_f = f;
                KEX_K = DiffieHellmanX.ComputeK(f);

                nbw5.WriteString(V_C);
                nbw5.WriteString(V_S);
                nbw5.WriteBlob(I_C);
                nbw5.WriteBlob(I_S);
                nbw5.WriteBlob(K_S);
                nbw5.WriteMPInt(HHH_e);
                nbw5.WriteMPInt(HHH_f);
                nbw5.WriteMPInt(KEX_K);
                nbw5.Flush();


                HashAlgorithm hash = SHA1.Create();
                byte[] xxx = ms5.ToArray();

                HEX_H = hash.ComputeHash(xxx);


                //CryptoStream cs = new CryptoStream(null, sha1, CryptoStreamMode.Write);
                /*
                buf.reset();
                    buf.putString(V_C);
                 * buf.putString(V_S);
                    buf.putString(I_C);
                 * buf.putString(I_S);
                    buf.putString(K_S);
                    buf.putMPInt(e);
                 * buf.putMPInt(f);
                    buf.putMPInt(K);
                    byte[] foo=new byte[buf.getLength()];
                    buf.getByte(foo);
                    sha.update(foo, 0, foo.Length);
                    H=sha.digest();
                 * cs.Write(  foo , 0, foo.Length);
                 * 
                 * sig.update(H);
                 * */

                RSAKeyInfo.Modulus = b_n2;
                RSAKeyInfo.Exponent = b_e;
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.ImportParameters(RSAKeyInfo);
                RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
                RSADeformatter.SetHashAlgorithm("SHA1");

                SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
                CryptoStream cs = new System.Security.Cryptography.CryptoStream(System.IO.Stream.Null, sha1, CryptoStreamMode.Write);
                cs.Write(HEX_H, 0, HEX_H.Length);
                cs.Close();


                bool verify = RSADeformatter.VerifySignature(sha1, rsa_signature_blob);
            }


            // Key Exchange
            byte[] kex_newkeys = TerminalClient.ParsePackage(nbr);

            byte[] kex_newkeys_p = TerminalClient.CreatePackage(kex_newkeys);
            nbw.WriteBytes(kex_newkeys_p);
            nbw.Flush();

            byte[] xxxxxxxxxx;
            HashAlgorithm hash_key = SHA1.Create();
            //
            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x41);
                nbw_cache.WriteBytes(HEX_H);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] IVc2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x42);
                nbw_cache.WriteBytes(HEX_H);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] IVs2c = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x43);
                nbw_cache.WriteBytes(HEX_H);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] Ec2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x44);
                nbw_cache.WriteBytes(HEX_H);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] Es2c = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x45);
                nbw_cache.WriteBytes(HEX_H);
                xxxxxxxxxx = ms_cache.ToArray();
            }
            byte[] MACc2s = hash_key.ComputeHash(xxxxxxxxxx);

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                nbw_cache.WriteMPInt(KEX_K);
                nbw_cache.WriteBytes(HEX_H);
                nbw_cache.WriteByte((byte)0x46);
                nbw_cache.WriteBytes(HEX_H);
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


            ICryptoTransform cipher_c2s = rijndael.CreateEncryptor(Ec2s, IVc2s);
            ICryptoTransform cipher_s2c = rijndael.CreateDecryptor(Es2c, IVs2c);

            // auth

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                //SSH_MSG_USERAUTH_REQUEST
                nbw_cache.WriteByte(5);
                nbw_cache.WriteString("ssh-userauth");


                byte[] packet = TerminalClient.CreatePackage(ms_cache.ToArray());
                packet = TerminalClient.MakePadding(packet, 16);

                HashAlgorithm hash_mac = SHA1.Create();
                byte[] mac = TerminalClient.ComputeMAC(MACc2s, 3, packet, hash_mac);
                cipher_c2s.TransformBlock(packet, 0, packet.Length, packet, 0);

                nbw.WriteBytes(packet);
                nbw.WriteBytes(mac);
                nbw.Flush();


                byte[] recv = nbr.ReadBytes(32);

                cipher_s2c.TransformBlock(recv, 0, recv.Length, recv, 0);

                for (int i = 0; i < 32; i++)
                {
                    char c = (char)recv[i];
                    Console.Write(c);
                }

                recv = nbr.ReadBytes(20);

            }

            {
                MemoryStream ms_cache = new MemoryStream();
                NetworkByteWriter nbw_cache = new NetworkByteWriter(ms_cache);
                //SSH_MSG_USERAUTH_REQUEST
                nbw_cache.WriteByte(50);
                nbw_cache.WriteString("root");
                nbw_cache.WriteString("ssh-connection");
                nbw_cache.WriteString("password");
                nbw_cache.WriteByte((byte)0);
                nbw_cache.WriteString("root");

                // s2ccipher.init(Cipher.DECRYPT_MODE, Es2c, IVs2c);

                //rijndael = new RijndaelManaged();
               // rijndael.Mode = CipherMode.CBC;
               // rijndael.Padding = PaddingMode.None;
                //cipher_c2s = rijndael.CreateEncryptor(Ec2s, IVc2s);
                byte[] packet = TerminalClient.CreatePackage(ms_cache.ToArray());
                packet = TerminalClient.MakePadding(packet, 16);

                HashAlgorithm hash_mac = SHA1.Create();
                byte[] mac = TerminalClient.ComputeMAC(MACc2s, 4, packet, hash_mac);
                cipher_c2s.TransformBlock(packet, 0, packet.Length, packet, 0);

                nbw.WriteBytes(packet);
                nbw.WriteBytes(mac);
                nbw.Flush();

                const int SSH_MSG_USERAUTH_SUCCESS = 52;

                byte[] recv = nbr.ReadBytes(32);
                //cipher_s2c = rijndael.CreateDecryptor(Es2c, IVs2c);
                cipher_s2c.TransformBlock(recv, 0, recv.Length, recv, 0);

                for (int i = 0; i < 32; i++ )
                {
                    char c = (char)recv[i];
                    Console.Write(c);
                }

                if (SSH_MSG_USERAUTH_SUCCESS == recv[5])
                {
                    Console.WriteLine("oh ya!");
                }
            }

            int pos = 0;
            while (true)
            {
                char c = (char)nbr.ReadByte();
                Console.Write(c);
                // Console.Write(c + " " + ((int)c).ToString("X2"));
                pos++;
                if (pos == 16)
                {
                    Console.WriteLine();
                    pos = 0;
                }
                else
                {
                    Console.Write(" ");
                }
                // Console.Write(c);
            }

            int x = tc.ReceiveBufferSize;
        }

    }



    public class PackageKEXINIT
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

        public void Load(byte[] data) {
            MemoryStream ms = new MemoryStream(data);
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

        public void ReSet()
        {
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

        public byte[] Pack()
        {
            MemoryStream ms = new MemoryStream();
            NetworkByteWriter nbw = new NetworkByteWriter(ms);

            nbw.WriteByte(20);
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


            return ms.ToArray();
        }

        public static ExchangeMethods Negotiate(PackageKEXINIT client, PackageKEXINIT server) {
            ExchangeMethods em = new ExchangeMethods();
            em.kex_algorithms = findfit(client.kex_algorithms, server.kex_algorithms);
            em.server_host_key_algorithms = findfit(client.server_host_key_algorithms, server.server_host_key_algorithms);
            em.encryption_algorithms_client_to_server = findfit(client.encryption_algorithms_client_to_server, server.encryption_algorithms_client_to_server);
            em.encryption_algorithms_server_to_client = findfit(client.encryption_algorithms_server_to_client, server.encryption_algorithms_server_to_client);
            em.mac_algorithms_client_to_server = findfit(client.mac_algorithms_client_to_server, server.mac_algorithms_client_to_server);
            em.mac_algorithms_server_to_client = findfit(client.mac_algorithms_server_to_client, server.mac_algorithms_server_to_client);
            em.compression_algorithms_client_to_server = findfit(client.compression_algorithms_client_to_server, server.compression_algorithms_client_to_server);
            em.compression_algorithms_server_to_client = findfit(client.compression_algorithms_server_to_client, server.compression_algorithms_server_to_client);
            em.languages_client_to_server = findfit(client.languages_client_to_server, server.languages_client_to_server);
            em.languages_server_to_client = findfit(client.languages_server_to_client, server.languages_server_to_client);
            return em;
        }

        private static string findfit(string[] client, string[] server)
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


    }

    public class ExchangeMethods {
        public string kex_algorithms;
        public string server_host_key_algorithms;
        public string encryption_algorithms_client_to_server;
        public string encryption_algorithms_server_to_client;
        public string mac_algorithms_client_to_server;
        public string mac_algorithms_server_to_client;
        public string compression_algorithms_client_to_server;
        public string compression_algorithms_server_to_client;
        public string languages_client_to_server;
        public string languages_server_to_client;
    }



    public class DiffieHellmanX
    {
        static byte[] P2 = new byte[] { 0x00, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
            0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
            0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
            0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
            0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
            0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
            0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        static byte[] P14 = new byte[] { 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
            0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
            0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
            0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
            0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
            0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
            0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
            0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
            0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
            0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
            0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
            0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
            0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
            0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
            0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
            0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
            0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
            0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF
        };

        static byte[] PX = new byte[] { 0x00, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0x00
        };

        static byte[] PY = new byte[] { 0x00, 
            0xFF, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF, 0xF2, 0xFF,  0x00
        };

        static byte[] G = new byte[] { 0x02, 
        };

        /*
        public static BigInteger CreateE()
        {
            dh = new DiffieHellmanManaged(P2, G, 0);
            byte[] e_array = dh.CreateKeyExchange();
            Array.Reverse(e_array);
            BigInteger bi = new BigInteger(e_array);
            return bi;
        }

        public static BigInteger ComputeK(BigInteger f)
        {
            byte[] f_array = f.ToByteArray();
            Array.Reverse(f_array);
            byte[] K_array = dh.DecryptKeyExchange(f_array);
            Array.Reverse(K_array);
            BigInteger bi = new BigInteger(K_array);
            return bi;
        } 
         * */

        public static BigInteger CreateE()
        {
            byte[] p2 = (byte[])P2.Clone();
            Array.Reverse(p2);
            BigInteger p = new BigInteger(p2);
            BigInteger g = new BigInteger(2);
            BigInteger x = new BigInteger(PX);


            BigInteger x_p = BigInteger.ModPow(g, x, p);

            return x_p;
        }

        public static BigInteger ComputeK(BigInteger f)
        {
            byte[] p2 = (byte[])P2.Clone();
            Array.Reverse(p2);
            BigInteger p = new BigInteger(p2);
            BigInteger g = new BigInteger(2);
            BigInteger x = new BigInteger(PX);

            BigInteger k1 = BigInteger.ModPow(f, x, p);
            return k1;
        }


        public static void Debug()
        {

            //MPInt m = new MPInt();
            //byte[] sss = m.ToByteArray();
            //byte[] ss1 = m.ToByteArray();

            //sss[0] = 1;

            /*
            byte[] p2 = (byte[])P2.Clone();
            Array.Reverse(p2);
            BigInteger p = new BigInteger(p2);
            BigInteger g = new BigInteger(2);
            BigInteger x = new BigInteger(PX);
            BigInteger x_p = BigInteger.ModPow(g, x, p);

            dh = new DiffieHellmanManaged(P2, G, 0);
            byte[] e_array = dh.CreateKeyExchange();
            Array.Reverse(e_array);
            BigInteger y_p = new BigInteger(e_array);









            byte[] f_array = x_p.ToByteArray();
            Array.Reverse(f_array);
            byte[] K_array = dh.DecryptKeyExchange(f_array);
            Array.Reverse(K_array);
            BigInteger bi = new BigInteger(K_array);


            BigInteger k1 = BigInteger.ModPow(y_p, x, p);
            byte[] K2_array = k1.ToByteArray();
             * 
             * */
        }
        
    }
}