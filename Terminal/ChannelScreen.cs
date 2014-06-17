using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace Terminal
{
    public class ChannelScreen
    {
        TextBox textbox;
        public void SetTextBox(TextBox t)
        {
            textbox = t;

        }
        public void HandleServerData(string data)
        {
            textbox.Dispatcher.BeginInvoke((Action)delegate()  
            {  
                textbox.Text += data; 
                textbox.SelectionStart = textbox.Text.Length;
                textbox.ScrollToEnd();
            });
        }

        string buff = "";
        public void HandleClientData(Key data)
        {
            if (data == Key.Return)
            {
                buff += "\n";
            } else if (data == Key.Space)
            {
                buff += " ";
            }
            else
            {
                buff += (char)KeyInterop.VirtualKeyFromKey(data);
            }
            
        }

        public void HandleClientData(string data)
        {
            buff += data;
        }

        public string GetClientData()
        {
            string temp = buff;
            buff = "";
            return temp;
        }
    }
}
