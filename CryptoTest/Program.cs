using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTest
{
    internal class Program
    {
        public static byte[] GenerateSalt(int size)
        {
            return RandomNumberGenerator.GetBytes(size);
        }

        public static string Encrypt(string clearText, string encryptionKey, string salt, int iterations)
        {
            try
            {
                byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, Encoding.UTF8.GetBytes(salt), iterations, HashAlgorithmName.SHA512);
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(clearBytes, 0, clearBytes.Length);
                            cs.Close();
                        }
                        clearText = Convert.ToBase64String(ms.ToArray());
                    }
                }
                return clearText;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"CryptographicException: {e.Message}");
                return "";
            }
            catch (ArgumentException e)
            {
                Console.WriteLine($"ArgumentException: {e.Message}");
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: {e.Message}");
                return "";
            }
        }

        public static string Decrypt(string cipherText, string encryptionKey, string salt, int iterations)
        {
            try
            {
                cipherText = cipherText.Replace(" ", "+");
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, Encoding.UTF8.GetBytes(salt), iterations, HashAlgorithmName.SHA512);
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        cipherText = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
                return cipherText;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"CryptographicException: {e.Message}");
                return "";
            }
            catch (ArgumentException e)
            {
                Console.WriteLine($"ArgumentException: {e.Message}");
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: {e.Message}");
                return "";
            }
        }

        private static Random random = new Random();

        public static string GeneratePassword()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#!%$";
            StringBuilder password = new StringBuilder();

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = random.Next(chars.Length);
                    password.Append(chars[index]);
                }

                if (i < 2) 
                {
                    password.Append('_');
                }
            }

            return password.ToString();
        }

        static void Main(string[] args)
        {
            const int iterations = 10000;

            if (args.Length < 2)
            {
                throw new ArgumentException("Too few arguments");
            }

            string operation = args[0];
            if (operation == "-e")
            {
                bool delete = false;
                if (args.Contains("-delete"))
                {
                    delete = true;
                }

                string filename = args[1];
                if (!File.Exists(filename))
                {
                    throw new FileNotFoundException(filename);
                }

                byte[] contents = File.ReadAllBytes(filename);
                string contentsBase64 = Convert.ToBase64String(contents);

                byte[] salt = GenerateSalt(16);
                string saltString = Convert.ToBase64String(salt);

                string password = GeneratePassword();
                Console.WriteLine($"Random generated password: {password}");
                Console.WriteLine("Do you want to keep it? (y/n)");
                if(Console.ReadKey().Key == ConsoleKey.N)
                {
                    password = "";
                    do
                    {
                        Console.Write("Enter a password: ");
                        password = Console.ReadLine()!;
                    }
                    while (string.IsNullOrWhiteSpace(password));
                }

                string encrypted = Encrypt(contentsBase64, password, saltString, iterations);
                string output = $"{saltString}:{encrypted}";
                File.WriteAllText($"{filename}.enc", output);

                if(delete)
                {
                    File.Delete(filename);
                }
            }
            else if(operation == "-d")
            {
                bool delete = false;
                if (args.Contains("-delete"))
                {
                    delete = true;
                }

                string filename = args[1];
                if (!File.Exists(filename))
                {
                    throw new FileNotFoundException(filename);
                }

                string contents = File.ReadAllText(filename);
                string[] tokens = contents.Split(':');
                if(tokens.Length < 2)
                {
                    throw new Exception("Bad encrypted file");
                }

                string saltString = tokens[0];
                string encrypted = tokens[1];

                string password;
                do
                {
                    Console.Write("Enter the password: ");
                    password = Console.ReadLine()!;
                }
                while (string.IsNullOrWhiteSpace(password));

                try
                {
                    string decrypted = Decrypt(encrypted, password, saltString, iterations);
                    byte[] fromBase64 = Convert.FromBase64String(decrypted);
                    string converted = Encoding.UTF8.GetString(fromBase64);
                    Console.WriteLine($"Contents: {converted}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"ERROR: {e.Message}");
                }

                if (delete)
                {
                    File.Delete(filename);
                }
            }
            else
            {
                throw new ArgumentException($"Bad operation type {operation}");
            }
        }
    }
}
