using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Terminal
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            Thread tWriteToFile = new Thread(new ThreadStart(OpenSSH));
            tWriteToFile.IsBackground = true;
            tWriteToFile.Start();


            VideoTerminal_Main.Focus();
        }

        public void OpenSSH()
        {

            TerminalClient tc = new TerminalClient();
            //"192.168.192.200"
            tc.Connect("192.168.192.132", 22);
            tc.VersionExchange();
            tc.KeyExchangeInit();
            tc.KeyExchange(tc.algorithm_kex);
            tc.KeyExchangeFinal();
            HashAlgorithm hash_sha1 = SHA1.Create();
            tc.KeyVerify(tc.algorithm_server_host_key, hash_sha1);
            tc.PrepareCryptoTransforms();
            tc.Authenticate("root", "root");

            tc.OpenChannel(VideoTerminal_Main);
        }

        private void VideoTerminal_Main_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            string x = e.Text;
            Console.WriteLine(e.Text);
            VideoTerminal_Main.HandleClientData(e.Text);
            e.Handled = true;
        }

        private void VideoTerminal_Main_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter || e.Key == Key.Up || e.Key == Key.Space || e.Key == Key.Back)
            {
                Console.WriteLine(e.Key);
                VideoTerminal_Main.HandleClientData(e.Key);
                e.Handled = true;
            }
        }
    }
}
