using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Win32;

namespace AESinRSA
{
    class AESklas
    {
        AesCryptoServiceProvider AEScript;

        public AESklas()
        {
            AEScript = new AesCryptoServiceProvider();

            AEScript.BlockSize = 128;
            //AEScript.KeySize = 256;
            //AEScript.GenerateIV();
            AEScript.Padding = PaddingMode.PKCS7;
            AEScript.Mode = CipherMode.CFB;
        }
        public void AES_Encrypt(string inputFile, string password,int keysize)
        {

            switch (keysize)
            {
                case 256:
                    AEScript.KeySize = 256;
                    
                    break;
                case 128:
                    AEScript.KeySize = 128;
                    
                    break;
                case 192:
                    
                    AEScript.KeySize = 192;
                    break;
                default:
                    
                    AEScript.KeySize = 256;
                    break;
            }

            byte[] gesloSkriv = UstvariSol();

            FileStream dat = new FileStream(inputFile + ".aes", FileMode.Create);

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            var kljuc = new Rfc2898DeriveBytes(passwordBytes, gesloSkriv, 50000);
            AEScript.Key = kljuc.GetBytes(AEScript.KeySize / 8);
            AEScript.IV = kljuc.GetBytes(AEScript.BlockSize / 8);

            dat.Write(gesloSkriv, 0, gesloSkriv.Length);

            CryptoStream enkrip = new CryptoStream(dat, AEScript.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream vpisi = new FileStream(inputFile, FileMode.Open);

            byte[] blok = new byte[1048576];
            int st;

            while ((st = vpisi.Read(blok, 0, blok.Length)) > 0)
            {
               enkrip.Write(blok, 0, st);
            }

            vpisi.Close();

            enkrip.Close();
            dat.Close();
            AEScript.Clear();

        }

        public void AES_Decrypt(string inputFile, string password, int keysize, out string mm)
        {
            mm = "";
 
            switch (keysize)
            {
                case 256:
                    AEScript.KeySize = 256;
                    break;
                case 128:
                    AEScript.KeySize = 128;
                    break;
                case 192:
                    AEScript.KeySize = 192;
                    break;
                default:
                    AEScript.KeySize = 256;
                    break;
            }

            byte[] kodaKluc = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] gesloSkriv = new byte[32];

            FileStream datNot = new FileStream(inputFile, FileMode.Open);
            datNot.Read(gesloSkriv, 0, gesloSkriv.Length);

            var key = new Rfc2898DeriveBytes(kodaKluc, gesloSkriv, 50000);
            AEScript.Key = key.GetBytes(AEScript.KeySize / 8);
            AEScript.IV = key.GetBytes(AEScript.BlockSize / 8);

            CryptoStream kodirni = new CryptoStream(datNot, AEScript.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream shrani = new FileStream(inputFile + ".dekriptirano", FileMode.Create);

            int st;
            byte[] bloki = new byte[1048576];

            try
            {
                while ((st = kodirni.Read(bloki, 0, bloki.Length)) > 0)
                {
                    shrani.Write(bloki, 0, st);
                }
            }
            catch (System.Security.Cryptography.CryptographicException ex_CryptographicException)
            {
                mm = "Napacen kljuc";
            }


            try
            {
                kodirni.Close();
            }
            catch (Exception ex)
            {
            }
            finally
            {
                shrani.Close();
                datNot.Close();
                AEScript.Clear();

            }
        }

        public byte[] UstvariSol()
        {

            byte[] sol = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                for (int i = 0; i < 10; i++)
                    rng.GetBytes(sol);

            return sol;
        }
        public void RSAEncrypt(string klucEnkrip)
        {
            var RSAENK = new RSACryptoServiceProvider();

            string publPrivKluc = RSAENK.ToXmlString(true);  
            byte[] dataZaEnk = Encoding.ASCII.GetBytes(klucEnkrip);
            byte[] EnkrRsa = RSAENK.Encrypt(dataZaEnk, false);

            SaveFileDialog fil = new SaveFileDialog();
            fil.Title = "Shranjevanje kljuca v Xml";
            if (fil.ShowDialog() == true)
            {
                File.WriteAllText(fil.FileName + ".xml",publPrivKluc);
            }
            fil.Title = "Shranjevanje eknriptirane vrednosti";
            if (fil.ShowDialog() == true)
            {
                File.WriteAllBytes(fil.FileName + ".txt", EnkrRsa);
            }

        }
        public string RSADecript(string klu,string en)
        {
            string kluc=klu,enk=en;
            
            var RSAENK = new RSACryptoServiceProvider();

            RSAENK.FromXmlString(kluc);

            byte[] ekrip = File.ReadAllBytes(enk);

            byte[] DekriptRsa = RSAENK.Decrypt(ekrip, false);

            string rezult = Encoding.Default.GetString(DekriptRsa);

            return rezult;
        }



    }
}
