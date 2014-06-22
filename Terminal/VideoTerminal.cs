using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
using System.Windows.Threading;

namespace Terminal
{
    public class VideoTerminal : FrameworkElement
    {
        static VideoTerminal()
        {
            
        }
        public Size CharSize { get; set; }
        public Typeface CharFont = new Typeface("Consolas, Simsun");
        public double CharFontSize = 12;
        public Thickness Padding { get; set; }
        Pen CaretPen;
        public Brush Foreground { get; set; }
        public Brush Background { get; set; }
        VideoTerminalCaret caret;
        VideoTerminalScreen screen;
        public VideoTerminal()
        {
            CharSize = new Size(7, 14);
            Padding = new Thickness(4);
            Foreground = Brushes.White;
            Background = Brushes.Black;
            CaretPen = new Pen(Foreground, 2);
            caret = new VideoTerminalCaret(this);
            screen = new VideoTerminalScreen(this);
            this.AddVisualChild(caret);
            this.AddVisualChild(screen);
        }

        class VideoTerminalCaret : UIElement
        {
            public int Column { get; set; }
            public int Row { get; set; }
            bool blinkvisible;
            DispatcherTimer blinktimer;
            VideoTerminal videoterminal;
            public VideoTerminalCaret(VideoTerminal parent)
            {
                videoterminal = parent;
                blinkvisible = true;
                blinktimer = new DispatcherTimer();
                blinktimer.Interval = new TimeSpan(0, 0, 0, 0, 500);
                blinktimer.Tick += new EventHandler(Blink);
                blinktimer.Start();
            }
            void Blink(object sender, EventArgs e)
            {
                blinkvisible = !blinkvisible;
                InvalidateVisual();
            }
            void Refresh()
            {
                InvalidateVisual();
            }
            protected override void OnRender(DrawingContext dc)
            {
                if (blinkvisible)
                {
                    Point coordinate = new Point();
                    coordinate.Y = (double)Row * videoterminal.CharSize.Height + videoterminal.Padding.Top;
                    coordinate.X = Column * videoterminal.CharSize.Width + videoterminal.Padding.Left;
                    dc.DrawLine(videoterminal.CaretPen, coordinate, new Point(coordinate.X, coordinate.Y + videoterminal.CharSize.Height));
                }
            }
        }

        

        class VideoTerminalScreen : FrameworkElement
        {
            VideoTerminal videoterminal;
            public bool Ready = true;
            public VideoTerminalChar[,] Buffer
            {
                get
                {
                    return (VideoTerminalChar[,])GetValue(BufferProperty);
                }
                set
                {
                    SetValue(BufferProperty, value);
                }
            }

            public VideoTerminalScreen(VideoTerminal parent)
            {
                videoterminal = parent;
                Buffer = new VideoTerminalChar[80, 24];
                for (int i = 0; i < 80; i++)
                {
                    for (int j = 0; j < 24; j++)
                    {
                        Buffer[i, j] = new VideoTerminalChar(videoterminal);
                    }
                }
            }

            public static readonly DependencyProperty BufferProperty = DependencyProperty.Register("Buffer", typeof(VideoTerminalChar[,]), typeof(VideoTerminalScreen), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
            protected override void OnRender(DrawingContext drawingContext)
            {
                base.OnRender(drawingContext);
                if (Ready == false)
                {
                    string testString = "Terminal Sharp\r\nA full C# based ssh2 terminal";

                    // Create the initial formatted text string.
                    FormattedText formattedText = new FormattedText(
                        testString,
                        CultureInfo.GetCultureInfo("en-us"),
                        FlowDirection.LeftToRight,
                        new Typeface("Verdana"),
                        32,
                        Brushes.Black);
                    formattedText.SetFontSize(36 * (96.0 / 72.0), 0, 15);
                    formattedText.SetFontWeight(FontWeights.Bold, 0, 8);
                    formattedText.SetForegroundBrush(new LinearGradientBrush(Colors.Orange, Colors.Teal, 90.0), 9, 5);
                    drawingContext.DrawText(formattedText, new Point(10, 0));

                }
                else
                {
                    drawingContext.DrawRectangle(videoterminal.Background, null, new Rect(new Point(0, 0), new Point(80 * 7 + 8, 24 * 14 + 8)));

                    for (int i = 0; i < 80; i++)
                    {
                        for (int j = 0; j < 24; j++)
                        {
                            drawingContext.DrawText(Buffer[i, j].GetFormattedText(), new Point(i * 7 + 4, j * 14 + 4));
                        }
                    }
                }
            }
        }

        class VideoTerminalChar
        {
            public int Width {get; private set;} // such as 0, 1, 2
            public string Value { get; private set; }
            static CultureInfo cultureinfo = CultureInfo.GetCultureInfo("en-us");
            static FlowDirection flowdirection = FlowDirection.LeftToRight;
            FormattedText formattedText;
            VideoTerminal videoterminal;
            public VideoTerminalChar(VideoTerminal parent)
            {
                videoterminal = parent;
                Format("", 0);
            }
            public VideoTerminalChar(VideoTerminal parent, char c)
            {
                videoterminal = parent;
                Format(c.ToString(), 1);
            }
            public VideoTerminalChar(VideoTerminal parent, char c, int width)
            {
                videoterminal = parent;
                Format(c.ToString(), width);
            }
            public FormattedText GetFormattedText()
            {
                return formattedText;
            }
            void Format(string value, int width)
            {
                Value = value;
                formattedText = new FormattedText(Value, cultureinfo, flowdirection, videoterminal.CharFont, videoterminal.CharFontSize, videoterminal.Foreground);
            }
        }
        

        protected override int VisualChildrenCount
        {
            get { return 2; }
        }

        // Provide a required override for the GetVisualChild method.
        protected override Visual GetVisualChild(int index)
        {
            switch (index)
            {
                default:
                case 1:
                    return caret;
                case 0:
                    return screen;
            }
        }
      
        protected override Size MeasureOverride(Size availableSize)
        {
            if (this.VisualChildrenCount > 0)
            {
                UIElement child = this.GetVisualChild(0) as UIElement;
                child.Measure(availableSize);

                child = this.GetVisualChild(1) as UIElement;
                child.Measure(availableSize);
                //return child.DesiredSize;
            }

            return availableSize;
        }
    

        protected override Size ArrangeOverride(Size finalSize)
        {
            Rect arrangeRect = new Rect()
            {
                Width = finalSize.Width,
                Height = finalSize.Height
            };

            if (this.VisualChildrenCount > 0)
            {
                UIElement child = this.GetVisualChild(0) as UIElement;
                child.Arrange(arrangeRect);

                child = this.GetVisualChild(1) as UIElement;
                child.Arrange(arrangeRect);
            }

            return finalSize;
        }

        protected override void OnRender(DrawingContext drawingContext)
        {
        }

        private void PushCharToTerminal(char ch)
        {
            screen.Ready = true;
            int width = TerminalMist.GetCharWidth(ch);
            if (width == 0 && ch != 0) return;
            VideoTerminalChar c;
            if (ch == 0)
            {
                c = new VideoTerminalChar(this);
            }
            else
            {
                c = new VideoTerminalChar(this, ch);
            }
            screen.Buffer[caret.Column, caret.Row] = c;
            caret.Column++;
            AdjustTerminalCaret();
            if (width == 2)
            {
                PushCharToTerminal((char)0);
            }
        }

        private void AdjustTerminalCaret()
        {
            if (caret.Row == 24)
            {
                for (int j = 1; j < 24; j++)
                {
                    for (int i = 0; i < 80; i++)
                    {
                        screen.Buffer[i, j - 1] = screen.Buffer[i, j];
                    }
                }
                for (int i = 0; i < 80; i++)
                {
                    screen.Buffer[i, 23] = new VideoTerminalChar(this);
                }
                caret.Row--;
            }
            if (caret.Column == 80)
            {
                caret.Column = 0;
                caret.Row++;
            }
            if (caret.Row == 24)
            {
                for (int j = 1; j < 24; j++)
                {
                    for (int i = 0; i < 80; i++)
                    {
                        screen.Buffer[i, j - 1] = screen.Buffer[i, j];
                    }
                }
                for (int i = 0; i < 80; i++)
                {
                    screen.Buffer[i, 23] = new VideoTerminalChar(this);
                }
                caret.Row--;
            }
        }

        int state_input = 0;
        List<char> state_cache = new List<char>();
        public void HandleServerData(string data)
        {

            screen.Dispatcher.Invoke(DispatcherPriority.Render, (Action)delegate() { });
            screen.Dispatcher.BeginInvoke((Action)delegate()
            {
            char[] chars = data.ToCharArray();
            foreach (char c in chars)
            {
                if (state_input == 0)
                {
                    switch (c)
                    {
                        case '\a':
                            break;
                        case '\r':
                            caret.Column = 0;
                            break;
                        case '\n':
                            caret.Row++;
                            break;
                        case '\b':
                            if (caret.Column > 0)
                            {
                                caret.Column -= 1;

                                AdjustTerminalCaret();
                            }
                            break;
                        case (char)27:
                            state_cache.Add((char)27);
                            state_input = 1;
                            break;
                        default:
                            PushCharToTerminal(c);
                            break;
                    }
                    AdjustTerminalCaret();
                }
                else if (state_input == 1)
                {
                    switch (c)
                    {
                        case '[':
                            state_cache.Add('[');
                            state_input = 2;
                            break;
                        default:
                            foreach (char cs in state_cache)
                            {
                                PushCharToTerminal(cs);
                            }
                            PushCharToTerminal(c);
                            break;
                    }
                }
                else if (state_input == 2)
                {
                    if ((c >= '0' && c <= '9') || c == ';')
                    {
                        state_cache.Add(c);
                    }
                    else
                    {
                        if (c == 'm')
                        {
                        }
                        else if (c == 'K')
                        {
                            for (int i = caret.Column; i < 80; i++)
                            {
                                screen.Buffer[i, caret.Row] = new VideoTerminalChar(this);
                            }
                        }
                        else if (c == 'C')
                        {
                            char[] x = state_cache.ToArray();
                            string s = new String(x, 2, x.Length - 2);
                            int pad = 1;
                            if (s.Length != 0)
                            {
                                pad = Int32.Parse(s);
                            }
                            for (int i = 0; i < pad; i++)
                            {
                                caret.Column++;
                                AdjustTerminalCaret();
                            }
                        }
                        else if (c == 'A')
                        {
                            caret.Row--;
                        }
                        else if (c == 'H')
                        {
                            char[] x = state_cache.ToArray();
                            string s = new String(x, 2, x.Length - 2);
                            string[] xx = s.Split(";".ToArray(), StringSplitOptions.RemoveEmptyEntries);
                            int xxx_x = 0;
                            int xxx_y = 0;
                            if (xx.Length != 0)
                            {
                                xxx_x = Int32.Parse(xx[1]) - 1;
                                xxx_y = Int32.Parse(xx[0]) - 1;
                            }
                            caret.Column = xxx_x;
                            caret.Row = xxx_y;
                        }
                        else if (c == 'J')
                        {
                            for (int j = 0; j < 24; j++)
                            {
                                for (int i = 0; i < 80; i++)
                                {
                                    screen.Buffer[i, j] = new VideoTerminalChar(this);
                                }
                            }
                        }
                        else if (c == 'r')
                        { }
                        else
                        {
                            foreach (char cs in state_cache)
                            {
                                PushCharToTerminal(cs);
                            }
                            PushCharToTerminal(c);
                        }
                        AdjustTerminalCaret();
                        state_cache = new List<char>();
                        state_input = 0;
                    }
                }


                
            }
            VideoTerminalChar[,] XXX = (VideoTerminalChar[,])screen.Buffer.Clone();
            screen.Buffer = XXX;
            });
        }

        string buff = "";
        public void HandleClientData(Key data)
        {
            if (data == Key.Return)
            {
                buff += "\n";
            }
            else if (data == Key.Space)
            {
                buff += " ";
            }
            else if (data == Key.Up)
            {
                buff += (char)0x0B;
            }
            else if (data == Key.Left)
            {
                buff += (char)0x09;
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
