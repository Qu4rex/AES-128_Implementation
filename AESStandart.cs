using System;
using System.Security.Cryptography;

public class AESStandard
{
    public byte[] EncryptECB(byte[] input, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = new byte[16]; 

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(input, 0, input.Length);
            }
        }
    }

    public byte[] DecryptECB(byte[] input, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = new byte[16]; 

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(input, 0, input.Length);
            }
        }
    }
    public byte[] EncryptCBC(byte[] input, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = iv;

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(input, 0, input.Length);
            }
        }
    }

    public byte[] DecryptCBC(byte[] input, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = iv;

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(input, 0, input.Length);
            }
        }
    }
}