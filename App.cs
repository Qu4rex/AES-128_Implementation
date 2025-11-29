using System;
using System.Text;
using System.Diagnostics;

namespace MyApp
{
    class App
    {
        static void Main(string[] args)
        {
            EnvReader.Load(".env");

            Console.WriteLine();
            string plaintext = "sometext";
            string key = Environment.GetEnvironmentVariable("KEY");
            string iv = "1234567890ABCDEF";

            Console.WriteLine($"Plaintext: {plaintext}");
            Console.WriteLine($"Key: {key}");
            Console.WriteLine($"IV: {iv}");
            Console.WriteLine();

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            Console.WriteLine("Выберите режим шифрования:");
            Console.WriteLine("1 - ECB Mode");
            Console.WriteLine("2 - CBC Mode");
            Console.Write("Выберите режим: ");

            string input = Console.ReadLine();

            switch (input)
            {
                case "1":
                    Console.WriteLine("=== ECB Mode ===");
                    TestECB(plaintextBytes, keyBytes);
                    break;
                case "2":
                    Console.WriteLine("=== CBC Mode ===");
                    TestCBC(plaintextBytes, keyBytes, ivBytes);
                    break;
                default:
                    Console.WriteLine("Неверный ввод.");
                    break;
            }
        }

        static void TestECB(byte[] plaintextBytes, byte[] keyBytes)
        {
            AESCustom aesCustom = new AESCustom();
            AESStandard aesStandard = new AESStandard();
            Stopwatch sw = new Stopwatch();

            sw.Start();
            byte[] encryptedCustom = aesCustom.EncryptECB(plaintextBytes, keyBytes);
            sw.Stop();
            long encryptCustomTime = sw.ElapsedTicks;

            sw.Restart();
            byte[] decryptedCustom = aesCustom.DecryptECB(encryptedCustom, keyBytes);
            sw.Stop();
            long decryptCustomTime = sw.ElapsedTicks;


            byte[] encryptedStandard = aesStandard.EncryptECB(plaintextBytes, keyBytes);
            byte[] decryptedStandard = aesStandard.DecryptECB(encryptedStandard, keyBytes);

            string encryptedCustomHex = BitConverter.ToString(encryptedCustom).Replace("-", "");
            string encryptedStandardHex = BitConverter.ToString(encryptedStandard).Replace("-", "");
            Console.WriteLine($"Custom Encrypted (Hex):  {encryptedCustomHex}");
            Console.WriteLine($"Standard Encrypted (Hex): {encryptedStandardHex}");

            string decryptedCustomText = Encoding.UTF8.GetString(decryptedCustom);
            string decryptedStandardText = Encoding.UTF8.GetString(decryptedStandard);
            Console.WriteLine($"Custom Decrypted:  {decryptedCustomText}");
            Console.WriteLine($"Standard Decrypted: {decryptedStandardText}");

            double msPerTick = 1000.0 / Stopwatch.Frequency;
            Console.WriteLine("\nExecution Time (ms):");
            Console.WriteLine($"Custom Encryption:  {encryptCustomTime * msPerTick:F4} ms");
            Console.WriteLine($"Custom Decryption:  {decryptCustomTime * msPerTick:F4} ms");
        }

        static void TestCBC(byte[] plaintextBytes, byte[] keyBytes, byte[] ivBytes)
        {
            AESCustom aesCustom = new AESCustom();
            AESStandard aesStandard = new AESStandard();
            Stopwatch sw = new Stopwatch();

            sw.Start();
            byte[] encryptedCustom = aesCustom.EncryptCBC(plaintextBytes, keyBytes, ivBytes);
            sw.Stop();
            long encryptCustomTime = sw.ElapsedTicks;

            sw.Restart();
            byte[] decryptedCustom = aesCustom.DecryptCBC(encryptedCustom, keyBytes, ivBytes);
            sw.Stop();
            long decryptCustomTime = sw.ElapsedTicks;

            byte[] encryptedStandard = aesStandard.EncryptCBC(plaintextBytes, keyBytes, ivBytes);
            byte[] decryptedStandard = aesStandard.DecryptCBC(encryptedStandard, keyBytes, ivBytes);

            string encryptedCustomHex = BitConverter.ToString(encryptedCustom).Replace("-", "");
            string encryptedStandardHex = BitConverter.ToString(encryptedStandard).Replace("-", "");
            Console.WriteLine($"Custom Encrypted (Hex):  {encryptedCustomHex}");
            Console.WriteLine($"Standard Encrypted (Hex): {encryptedStandardHex}");

            string decryptedCustomText = Encoding.UTF8.GetString(decryptedCustom);
            string decryptedStandardText = Encoding.UTF8.GetString(decryptedStandard);
            Console.WriteLine($"Custom Decrypted:  {decryptedCustomText}");
            Console.WriteLine($"Standard Decrypted: {decryptedStandardText}");

            double msPerTick = 1000.0 / Stopwatch.Frequency;
            Console.WriteLine("\nExecution Time (ms):");
            Console.WriteLine($"Custom Encryption:  {encryptCustomTime * msPerTick:F4} ms");
            Console.WriteLine($"Custom Decryption:  {decryptCustomTime * msPerTick:F4} ms");
        }
    }

    class EnvReader
    {
        public static void Load(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"The file '{filePath}' does not exist.");

            foreach (var line in File.ReadAllLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                var parts = line.Split('=', 2);
                if (parts.Length != 2)
                    continue;

                var key = parts[0].Trim();
                var value = parts[1].Trim();
                Environment.SetEnvironmentVariable(key, value);
            }
        }
    }
}