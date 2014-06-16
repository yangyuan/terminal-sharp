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
            HashAlgorithm hash = MD5.Create();


            TerminalClient tc = new TerminalClient();
            tc.Connect("192.168.192.200", 22);
            tc.VersionExchange();
            tc.KeyExchangeInit();
            tc.KeyExchange(tc.algorithm_kex);
            tc.KeyExchangeFinal();
            HashAlgorithm hash_sha1 = SHA1.Create();
            tc.KeyVerify(tc.algorithm_server_host_key, hash_sha1);
            tc.PrepareCryptoTransforms();
            tc.Authenticate();
        }

    }
}