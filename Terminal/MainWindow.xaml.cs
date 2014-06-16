using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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

            TerminalClient tc = new TerminalClient();
            tc.Connect("192.168.192.132", 22);
            tc.VersionExchange();
            tc.KeyExchangeInit();
            tc.KeyExchange(tc.algorithm_kex);
            tc.KeyExchangeFinal();
            HashAlgorithm hash_sha1 = SHA1.Create();
            tc.KeyVerify(tc.algorithm_server_host_key, hash_sha1);
            tc.PrepareCryptoTransforms();
            tc.Authenticate();
            tc.OpenChannel();
        }


        private void TextBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            Console.WriteLine(e.Key);
            e.Handled = true;
        }
    }
}
