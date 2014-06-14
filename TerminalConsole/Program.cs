using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using Terminal;

namespace TerminalConsole
{
    class Program
    {
        static void Main(string[] args)
        {
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




            int pos = 0;
            while (true)
            {
                char c = (char)nbr.ReadByte();
                Console.Write(c + " " + ((int)c).ToString("X2"));
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
            mac_algorithms_client_to_server = new string[] { "hmac-sha1-96", "hmac-sha1" };
            mac_algorithms_server_to_client = new string[] { "hmac-sha1-96", "hmac-sha1" };
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
}
