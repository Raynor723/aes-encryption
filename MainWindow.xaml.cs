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
using System.Windows.Shapes;
using System.IO;
using System.Security.Cryptography;

namespace aes_encryption
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
        public void encryptionButton(object sender, RoutedEventArgs e)
        {
            try
            {

                string Ciphertext = EncryptString(IntText.Text, ParseHex(ComputeSha256Hash(KeyIn.Text)));
                OutCiphertext.Clear();
                OutCiphertext.AppendText(Ciphertext);
            }
            catch
            {

            }
        }
        public void decryptionButton(object sender, RoutedEventArgs e)
        {
            try
            {
                DecryptedTextOut.Clear();
                string Ciphertext2 = IntCiphertext.Text;
                string DecryptText = DecryptString(Ciphertext2, ParseHex(ComputeSha256Hash(KeyIn.Text)));
                DecryptedTextOut.AppendText(DecryptText);
            }
            catch
            {

            }
        }

        public static string EncryptString(string text, byte[] key)
        {

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        public static string DecryptString(string cipherText, byte[] key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
        static string ComputeSha256Hash(string rawData)  //sha256
        {

            using (SHA256 sha256Hash = SHA256.Create())
            {

                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
        static byte[] ParseHex(string text) //sha to base64
        {
            Func<char, int> parseNybble = c => (c >= '0' && c <= '9') ? c - '0' : char.ToLower(c) - 'a' + 10;
            return Enumerable.Range(0, text.Length / 2).Select(x => (byte)((parseNybble(text[x * 2]) << 4) | parseNybble(text[x * 2 + 1]))).ToArray();
        }








    }
    
    
}
