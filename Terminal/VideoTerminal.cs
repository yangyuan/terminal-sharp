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
    /// <summary>
    /// Follow steps 1a or 1b and then 2 to use this custom control in a XAML file.
    ///
    /// Step 1a) Using this custom control in a XAML file that exists in the current project.
    /// Add this XmlNamespace attribute to the root element of the markup file where it is 
    /// to be used:
    ///
    ///     xmlns:MyNamespace="clr-namespace:Terminal"
    ///
    ///
    /// Step 1b) Using this custom control in a XAML file that exists in a different project.
    /// Add this XmlNamespace attribute to the root element of the markup file where it is 
    /// to be used:
    ///
    ///     xmlns:MyNamespace="clr-namespace:Terminal;assembly=Terminal"
    ///
    /// You will also need to add a project reference from the project where the XAML file lives
    /// to this project and Rebuild to avoid compilation errors:
    ///
    ///     Right click on the target project in the Solution Explorer and
    ///     "Add Reference"->"Projects"->[Browse to and select this project]
    ///
    ///
    /// Step 2)
    /// Go ahead and use your control in the XAML file.
    ///
    ///     <MyNamespace:VideoTerminal/>
    ///
    /// </summary>
    public class VideoTerminal : UserControl
    {
        static VideoTerminal()
        {
            DefaultStyleKeyProperty.OverrideMetadata(typeof(VideoTerminal), new FrameworkPropertyMetadata(typeof(VideoTerminal)));
        }
        class Caret : FrameworkElement
        {
            System.Threading.Timer timer;
            public double CaretHeight { get; set; }
            int blinkPeriod = 500;
            Pen pen = new Pen(Brushes.White, 2);

            public static readonly DependencyProperty VisibleProperty =
              DependencyProperty.Register("Visible", typeof(bool),
              typeof(Caret), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

            public static readonly DependencyProperty LocationPropertyX =
              DependencyProperty.Register("LocationX", typeof(int),
              typeof(Caret), new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));
            public static readonly DependencyProperty LocationPropertyY =
              DependencyProperty.Register("LocationY", typeof(int),
              typeof(Caret), new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));
            public Caret()
            {
                pen.Freeze();
                CaretHeight = 14;
                Visible = true;
                timer = new System.Threading.Timer(blinkCaret, null, 0, blinkPeriod);
            }
            Point location;
            protected override void OnRender(DrawingContext dc)
            {
                if (Visible)
                {
                    location.Y = (double)LocationY * 14 + 4;
                    location.X = LocationX * 7 + 4;
                    dc.DrawLine(pen, location, new Point(location.X, location.Y + CaretHeight));
                }
            }


            public int LocationX
            {
                get
                {
                    return (int)GetValue(LocationPropertyX);
                }
                set
                {
                    SetValue(LocationPropertyX, value);
                }
            }

            public int LocationY
            {
                get
                {
                    return (int)GetValue(LocationPropertyY);
                }
                set
                {
                    SetValue(LocationPropertyY, value);
                }
            }

            bool Visible
            {
                get
                {
                    return (bool)GetValue(VisibleProperty);
                }
                set
                {
                    SetValue(VisibleProperty, value);
                }
            }

            void blinkCaret(Object state)
            {
                Dispatcher.Invoke(new Action(delegate { Visible = !Visible; }));
            }
        }

        

        class Screen : FrameworkElement
        {
            string content = "";

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

            public bool Visible
            {
                get
                {
                    return (bool)GetValue(VisibleProperty);
                }
                set
                {
                    SetValue(VisibleProperty, value);
                }
            }

            public Screen()
            {
                Buffer = new VideoTerminalChar[80, 24];
                for (int i = 0; i < 80; i++)
                {
                    for (int j = 0; j < 24; j++)
                    {
                        Buffer[i, j] = new VideoTerminalChar();
                    }
                }
            }

            public static readonly DependencyProperty BufferProperty =
              DependencyProperty.Register("Buffer", typeof(VideoTerminalChar[,]),
              typeof(Screen), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

            public static readonly DependencyProperty VisibleProperty =
              DependencyProperty.Register("Visible", typeof(bool),
              typeof(Screen), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));
            protected override void OnRender(DrawingContext drawingContext)
            {
                base.OnRender(drawingContext);
                if (content == "")
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

                    content = "1";
                }
                else
                {
                    drawingContext.DrawRectangle(Brushes.Black, null, new Rect(new Point(0, 0), new Point(80 * 7 + 8, 24 * 14 + 8)));

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


        Caret caret = new Caret();
        Screen screen = new Screen();
        public VideoTerminal()
        {

            //this.AddChild(screen);
            this.AddVisualChild(caret);
            this.AddVisualChild(screen);
            this.Background = null;
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
        /*
        protected override Size MeasureOverride(Size availableSize)
        {
            if (this.VisualChildrenCount > 0)
            {
                UIElement child = this.GetVisualChild(0) as UIElement;
                child.Measure(availableSize);
                return child.DesiredSize;
            }

            return availableSize;
        }*/

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
            int width = TerminalMist.GetCharWidth(ch);
            if (width == 0 && ch != 0) return;
            VideoTerminalChar c;
            if (ch == 0)
            {
                c = new VideoTerminalChar();
            }
            else
            {
                c = new VideoTerminalChar(ch);
            }
            screen.Buffer[caret.LocationX, caret.LocationY] = c;
            caret.LocationX++;
            AdjustTerminalCaret();
            if (width == 2)
            {
                PushCharToTerminal((char)0);
            }
        }

        private void AdjustTerminalCaret()
        {
            if (caret.LocationY == 24)
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
                    screen.Buffer[i, 23] = new VideoTerminalChar();
                }
                caret.LocationY--;
            }
            if (caret.LocationX == 80)
            {
                caret.LocationX = 0;
                caret.LocationY++;
            }
            if (caret.LocationY == 24)
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
                    screen.Buffer[i, 23] = new VideoTerminalChar();
                }
                caret.LocationY--;
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
                            caret.LocationX = 0;
                            break;
                        case '\n':
                            caret.LocationY++;
                            break;
                        case '\b':
                            if (caret.LocationX > 0)
                            {
                                caret.LocationX -= 1;

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
                            for (int i = caret.LocationX; i < 80; i++)
                            {
                                screen.Buffer[i, caret.LocationY] = new VideoTerminalChar();
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
                                caret.LocationX++;
                                AdjustTerminalCaret();
                            }
                        }
                        else if (c == 'A')
                        {
                            caret.LocationY--;
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
                            caret.LocationX = xxx_x;
                            caret.LocationY = xxx_y;
                        }
                        else if (c == 'J')
                        {
                            for (int j = 0; j < 24; j++)
                            {
                                for (int i = 0; i < 80; i++)
                                {
                                    screen.Buffer[i, j] = new VideoTerminalChar();
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
            screen.Visible = false;
            screen.Visible = true;
            screen.Buffer = XXX;
            this.InvalidateVisual();
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



        class VideoTerminalChar
        {
            static CultureInfo cultureinfo = CultureInfo.GetCultureInfo("en-us");
            static FlowDirection flowdirection = FlowDirection.LeftToRight;
            static Typeface typeface = new Typeface("Consolas, Simsun");
            static double fontsize = 12;
            static Brush fontcolor = Brushes.White;

            FormattedText formattedText;
            string value;
            int width; // such as 0, 1, 2
            public VideoTerminalChar()
            {
                value = "";
                width = 0;
                UpdateFormattedText();
            }
            public VideoTerminalChar(char c)
            {
                value = c.ToString();
                width = 1;
                UpdateFormattedText();
            }
            public void UpdateFormattedText()
            {
                formattedText = new FormattedText(value, cultureinfo, flowdirection, typeface, fontsize, fontcolor);
            }
            public FormattedText GetFormattedText()
            {
                return formattedText;
            }
        }
    }
}
