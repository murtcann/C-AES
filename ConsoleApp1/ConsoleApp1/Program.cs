using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.Write("Text:");
        string metin = Console.ReadLine();

        using (Aes aes = Aes.Create())
        {
            byte[] pubkey;
            byte[] privkey;
            GenerateKeyPair(out privkey, out pubkey);

            byte[] encrypted = Encrypt(metin, pubkey, out byte[] startvector);
            Console.WriteLine("Encrypted Text: " + Convert.ToBase64String(encrypted));

            string decrypted = Decrypt(encrypted, privkey, startvector);
            Console.WriteLine("Decrypted Text: " + decrypted);
            Console.WriteLine("IV: " + Convert.ToBase64String(startvector));
        }
    }

    static void GenerateKeyPair(out byte[] pubkey, out byte[] privkey)
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();

            pubkey = aes.Key;
            privkey = aes.IV;
        }
    }

    static byte[] Encrypt(string metin, byte[] pubkey, out byte[] startvector)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = pubkey;
            aes.GenerateIV();
            startvector = aes.IV;

            ICryptoTransform encryptor = aes.CreateEncryptor();

            using (MemoryStream memos = new MemoryStream())
            {
                using (CryptoStream cros = new CryptoStream(memos, encryptor, CryptoStreamMode.Write))
                {
                    byte[] textbytes = Encoding.UTF8.GetBytes(metin);
                    cros.Write(textbytes, 0, textbytes.Length);
                    cros.FlushFinalBlock();
                    return memos.ToArray();
                }
            }
        }
    }

    static string Decrypt(byte[] encryptedData, byte[] privkey, byte[] startvector)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = privkey;
            aes.IV = startvector;
            aes.Padding = PaddingMode.PKCS7 | PaddingMode.Zeros;

            ICryptoTransform decryptor = aes.CreateDecryptor();

            using (MemoryStream memos = new MemoryStream(encryptedData))
            {
                using (CryptoStream cros = new CryptoStream(memos, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cros))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
    }
}
