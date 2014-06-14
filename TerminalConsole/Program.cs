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
            ParseKEX(kex);
            byte[] kexs = TerminalClient.CreatePackage(kex);
            nbw.WriteBytes(kexs);
            nbw.Flush();

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

        static void ParseKEX(byte[] data)
        {
            MemoryStream ms = new MemoryStream(data);
            NetworkByteReader nbr = new NetworkByteReader(ms);
            byte SSH_MSG_KEXINIT = nbr.ReadByte();
            byte[] cookie = nbr.ReadBytes(16);
            string[] kex_algorithms = nbr.ReadNameList();
            string[] server_host_key_algorithms = nbr.ReadNameList();
            string[] encryption_algorithms_client_to_server = nbr.ReadNameList();
            string[] encryption_algorithms_server_to_client = nbr.ReadNameList();
            string[] mac_algorithms_client_to_server = nbr.ReadNameList();
            string[] mac_algorithms_server_to_client = nbr.ReadNameList();
            string[] compression_algorithms_client_to_server = nbr.ReadNameList();
            string[] compression_algorithms_server_to_client = nbr.ReadNameList();
            string[] languages_client_to_server = nbr.ReadNameList();
            string[] languages_server_to_client = nbr.ReadNameList();
            bool first_kex_packet_follows = nbr.ReadBoolean();
            uint reserved = nbr.ReadUInt32();
        }
    }
}
