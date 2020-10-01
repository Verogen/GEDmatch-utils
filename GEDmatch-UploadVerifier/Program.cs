using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GEDmatch.UploadVerifier
{
    class Program
    {
        private static readonly byte[] _key = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
        private static readonly byte[] _initVector = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");

        static int Main(string[] args)
        {
            if (args[0] == null)
                return 1;

            return VerifyEncryptedHashCode(args[0])
                ? 0
                : 1;
        }

        public static bool VerifyEncryptedHashCode(string filePath)
        {
            string encryptedHashCode, fileContents;
            using (var reader = new StreamReader(new FileStream(filePath, FileMode.Open)))
            {
                encryptedHashCode = reader.ReadLine().Substring(1);
                fileContents = reader.ReadToEnd();
            }
            var MD5Hash = Convert.ToBase64String(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(fileContents)));
            var decrypted = AesDecrypt(encryptedHashCode, _key, _initVector);

            return MD5Hash == decrypted;
        }

        public static byte[] AesEncrypt(string plainText, byte[] key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        static string AesDecrypt(string cipherText, byte[] key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
