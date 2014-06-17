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
        }
        static void Main(string[] args)
        {
            HashAlgorithm hash = MD5.Create();

            TerminalClient tc = new TerminalClient();
            tc.Connect("192.168.192.132", 22);
            tc.VersionExchange();
            tc.KeyExchangeInit();
            tc.KeyExchange(tc.algorithm_kex);
            tc.KeyExchangeFinal();
            HashAlgorithm hash_sha1 = SHA1.Create();
            tc.KeyVerify(tc.algorithm_server_host_key, hash_sha1);
            tc.PrepareCryptoTransforms();
            tc.Authenticate("","");
            //tc.OpenChannel();
        }

    }
}