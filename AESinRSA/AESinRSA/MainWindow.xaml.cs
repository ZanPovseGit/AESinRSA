using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
//using System.Windows.Shapes;
using Microsoft.Win32;
using System.IO;

namespace AESinRSA
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();

            dialog.Multiselect = false;

            if (dialog.ShowDialog() == true)
            {
                pot.Text = dialog.FileName;
            }
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            AESklas mm = new AESklas();
            int a = 0; string izpis;
            if (int.TryParse(vel.Text, out a) == true)
            {
                if (aese.IsChecked == true)
                {
                    mm.AES_Encrypt(pot.Text, geslo.Text, int.Parse(vel.Text));
                }
                if (aesd.IsChecked == true)
                {
                    mm.AES_Decrypt(pot.Text, geslo.Text, int.Parse(vel.Text),out izpis);
                    if (izpis.Length == 0)
                    {
                        MessageBox.Show("Uspesno dekriptiranje");
                    }
                    else
                    {
                        MessageBox.Show(izpis);
                    }
                }
            }
            else
            {
                MessageBox.Show("Nepravilen vnos velikosti kjuca");
            }
        }

        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            AESklas mm = new AESklas();
            rsaen.Content = geslo.Text;
            if(rsaen.Content!=null)
            mm.RSAEncrypt(rsaen.Content.ToString());
        }

        private void Button_Click_3(object sender, RoutedEventArgs e)
        {
            AESklas mm = new AESklas();
            string ac = "";
            string kluc = "", enk = "";
            OpenFileDialog odpri = new OpenFileDialog();
            odpri.Title = "Kljuc za odkodiranje XML";
            odpri.Filter = "XML Files|*.xml";
            if (odpri.ShowDialog() == true)
            {
                
                kluc = odpri.FileName;
            }
            odpri.Title = "Kriptiran kljuc";
            odpri.Filter = "Text Files|*.txt";
            if (odpri.ShowDialog() == true)
            {
                
                enk = odpri.FileName;
            }
            kluc = File.ReadAllText(kluc);

             ac = mm.RSADecript(kluc, enk);

            dekripRSA.Content = ac;
        }
    }
}
