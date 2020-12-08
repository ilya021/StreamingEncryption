﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.IO;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace StreamingEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public class CryptoService
    {
        private CipherMode _cipherMode = CipherMode.CFB;
        private PaddingMode _paddingMode = PaddingMode.PKCS7;

        private static readonly byte[] _salt = new byte[] { 0x25, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x12, 0x3c };

        private EncryptionAlgorithm _algorithm = EncryptionAlgorithm.AES;
        public EncryptionAlgorithm Algorithm
        {
            get { return _algorithm; }
            set { _algorithm = value; }
        }

        public Stream Encrypt(Stream streamToEncrypt, byte[] key)
        {
            SymmetricAlgorithm algorithm = null;
            if (_algorithm == EncryptionAlgorithm.TripleDES)
                algorithm = new TripleDESCryptoServiceProvider();
            else if (_algorithm == EncryptionAlgorithm.AES)
                algorithm = new AesManaged();
            else
                throw new ApplicationException("21!");

            algorithm.Mode = _cipherMode;
            algorithm.Padding = _paddingMode;



            Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(key, _salt, 100);
            algorithm.Key = rfc.GetBytes(algorithm.KeySize / 8);
            algorithm.IV = rfc.GetBytes(algorithm.BlockSize / 8);

            try
            {
                ICryptoTransform encryptor = algorithm.CreateEncryptor();
                using (CryptoStream cryptoStream = new CryptoStream(streamToEncrypt, encryptor, CryptoStreamMode.Read))
                {
                    MemoryStream ms = new MemoryStream();
                    CopyStream(cryptoStream, ms);
                    ms.Seek(0, SeekOrigin.Begin);
                    return ms;
                }
            }
            finally
            {
                algorithm.Clear();
            }
        }

        public Stream Decrypt(Stream streamToDecrypt, byte[] key)
        {
            SymmetricAlgorithm algorithm = null;
            if (_algorithm == EncryptionAlgorithm.TripleDES)
                algorithm = new TripleDESCryptoServiceProvider();
            else if (_algorithm == EncryptionAlgorithm.AES)
                algorithm = new AesManaged();
            else
                throw new ApplicationException("Unexpected algorithm type!");

            algorithm.Mode = _cipherMode;
            //algorithm.Padding = _paddingMode;
            algorithm.Padding = PaddingMode.Zeros;


            Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(key, _salt, 100);
            algorithm.Key = rfc.GetBytes(algorithm.KeySize / 8);
            algorithm.IV = rfc.GetBytes(algorithm.BlockSize / 8);

            try
            {
                ICryptoTransform decryptor = algorithm.CreateDecryptor();
                using (CryptoStream cryptoStream = new CryptoStream(streamToDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    MemoryStream ms = new MemoryStream();
                    CopyStream(cryptoStream, ms);
                    ms.Seek(0, SeekOrigin.Begin);
                    return ms;
                }
            }
            finally
            {
                algorithm.Clear();
            }
        }

        public byte[] Encrypt(byte[] dataToEncrypt, byte[] key)
        {
            MemoryStream ms = new MemoryStream(dataToEncrypt);
            Stream res = Encrypt(ms, key);
            if (res != null)
            {
                byte[] tmp = new byte[res.Length];
                res.Read(tmp, 0, tmp.Length);
                return tmp;
            }

            return null;
        }

        public byte[] Decrypt(byte[] dataToDecrypt, byte[] key)
        {
            MemoryStream ms = new MemoryStream(dataToDecrypt);
            Stream res = Decrypt(ms, key);
            if (res != null)
            {
                byte[] tmp = new byte[res.Length];
                res.Read(tmp, 0, tmp.Length);
                return tmp;
            }

            return null;
        }

        public void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[32768];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
            }
        }
    }

    public enum EncryptionAlgorithm
    {
        TripleDES,
        AES,
    }
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        CryptoService cryptoService = new CryptoService();
        private void ButtonClickEncrypt(object sender, RoutedEventArgs e)
        {
            
            byte[] data = Encoding.Unicode.GetBytes(inputText.Text);
            byte[] key = Encoding.Unicode.GetBytes(keyWord.Text);

            byte[] cipherData = cryptoService.Encrypt(data, key);
            encryptedText.Text = Encoding.Unicode.GetString(cipherData);
        }
        private void ButtonClickDecrypt(object sender, RoutedEventArgs e)
        {
            
            byte[] data = Encoding.Unicode.GetBytes(inputText.Text);
            byte[] key = Encoding.Unicode.GetBytes(keyWord.Text);

            byte[] decryptedData = cryptoService.Decrypt(data, key);
            encryptedText.Text = Encoding.Unicode.GetString(decryptedData);
        }
    }
}
