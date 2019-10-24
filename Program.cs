using System;
using System.Text;
using AESEncryption;

namespace AESEncryption
{
    
    public static class Params
    {
        public static bool decrypt = false;
        public static bool verbose = false;
        public static bool useLabels = false;
        public static bool hex = false;
        public static bool base64 = true;
        public static bool usePadding = true;
        public static bool useKeyPadding = true;
        public static bool useCBC = false;

        public static KeySize keySize = KeySize.bit128; //Currently only the 128bit key size complies with the standard

        public static string key = "1111222233334444";
        public static string initVector = "1234567890123456";
        public static string text = "This is some test text that will";
    }

    class Program
    {
        static void Main(string[] args)
        {
            if(!ParseInput(args))
                return;

            if(Params.verbose)
            {   
                System.Console.WriteLine(Params.decrypt ? "Running in decryption mode." : "Running in endryption mode." );
                System.Console.WriteLine(Params.useCBC ? "Using CBC." : "Using ECB.");
                System.Console.WriteLine(Params.usePadding ? "Using PKCS5 padding." : "Not using padding. (Will fail if text length is not mod 16 byte.)");

                System.Console.WriteLine("Key: ({0})", Params.key);
                System.Console.WriteLine(BytesToFormatedString(Encoding.UTF8.GetBytes(Params.key)));
                System.Console.WriteLine();

                System.Console.WriteLine("Text: '{0}'", Params.text);
                System.Console.WriteLine(BytesToFormatedString(Encoding.UTF8.GetBytes(Params.text)));
                System.Console.WriteLine();

            }

            var cipher = new AESCipher(
                new AESParameters(
                    Encoding.UTF8.GetBytes(Params.key),
                    Params.keySize,
                    Params.useCBC,
                    Params.usePadding,
                    Params.useKeyPadding,
                    Encoding.UTF8.GetBytes(Params.initVector),
                    Params.verbose
                )
            );
            byte[] result;

            if(Params.decrypt)
                result = cipher.Decrypt(Convert.FromBase64String(Params.text));
            else
                result = cipher.Encrypt(Encoding.UTF8.GetBytes(Params.text));

            if(Params.hex)
            {
                if(Params.useLabels || Params.verbose)
                    System.Console.WriteLine("Result (Hex):");
                System.Console.WriteLine(BytesToFormatedString(result));              
            }

            if(Params.base64)
            {
                if(Params.useLabels || Params.verbose)
                    System.Console.WriteLine("Result (base64):");
                System.Console.WriteLine(Convert.ToBase64String(result));              
            }
                
            if(Params.decrypt)
            {
                if(Params.useLabels || Params.verbose)
                    System.Console.WriteLine("Result (utf-8):");
                System.Console.WriteLine(Encoding.UTF8.GetString(result));
            }

        }

        ///Parse cl parameters. Returns false if not to execute.
        static bool ParseInput(string[] args)
        {
            bool keySet = false,
                textSet = false,
                initVecSet = false;

            for(int i = 0; i < args.Length; i++)
            {
                if(args[i].StartsWith('-'))
                {
                    string arg = args[i].Trim().ToUpper();
                    if(arg == "-H" || arg == "--HELP")
                    {
                        Console.WriteLine("Structure:");
                        Console.WriteLine("[(param [param value])] [Key] Text ");
                        Console.WriteLine("Commands:");
                        Console.WriteLine("--decrypt \t| --decipher | -d \t: Decript given text using given parameters;");
                        Console.WriteLine("--verbose \t| -v \t: Output intermediate values;");
                        Console.WriteLine("--useLabels \t| -l \t: Label outputs;");
                        Console.WriteLine("--hex \t\t| -x \t: Turn on/off hex value output (off by default);");
                        Console.WriteLine("--base64 \t| -b \t: Turn on/off base64 value output (on by default);");
                        Console.WriteLine("--padding \t| -p \t: Turn on/off padding (on by default). \nIf off - will fail if input is not divisible by 16 bytes;");
                        Console.WriteLine("--cbc \t\t| -c  \t: Turn use CBC instead of ECB;");
                        Console.WriteLine("--keySize \t| -s  \t: Set key size to use (128, 192 or 256 bit key length) \n Currently only the 128bit key size complies with the standard;");
                        Console.WriteLine("--initVec \t| -i  \t: Set initialization vector for CBC mode;");
                        Console.WriteLine();

                        return false;
                    }
                    else if (arg == "-D" || arg == "--DECRYPT" || arg == "--DECIPHER")
                    {
                        Params.decrypt = !Params.decrypt;
                        Params.base64 = !Params.base64;
                    }
                    else if(arg == "-V" || arg == "--VERBOSE")
                        Params.verbose = !Params.verbose;
                    else if(arg == "-L" || arg == "--USELABELS")
                        Params.useLabels = !Params.useLabels;
                    else if(arg == "-X" || arg == "--HEX")
                        Params.hex = !Params.hex;
                    else if (arg == "-B" || arg == "--BASE64")
                        Params.base64 = !Params.base64;
                    else if (arg == "-P" || arg == "--PADDING")
                        Params.base64 = !Params.usePadding;
                    else if (arg == "-C" || arg == "--CBC")
                        Params.useCBC = !Params.useCBC; 
                    else if (arg == "-S" || arg == "--KEYSIZE")
                    {
                        i++;
                        if(args[i].Contains("128"))
                            Params.keySize = KeySize.bit128;
                        else if(args[i].Contains("192"))
                            Params.keySize = KeySize.bit192;
                        else if(args[i].Contains("256"))
                            Params.keySize = KeySize.bit256;
                        else
                        {
                            Console.WriteLine("Warning: unknown key size '{0}' entered. Valid sizes: '128', '192', '256'.");
                            return false;
                        }

                    }
                    else if (arg == "-I" || arg == "--INITVEC")
                    {
                        i++;
                        if(args[i].Length < 16)
                        {
                            Console.WriteLine("Warning: initialization vector mus be atleast 16 bytes.");
                            return false;
                        }
                        
                        Params.initVector = args[i].Substring(0,16);
                        initVecSet = true;
                    }
                }
                else if(i == args.Length - 1)
                {
                    Params.text = args[i];
                    textSet = true;
                }
                else if(!keySet)
                {
                    Params.key = args[i];
                    keySet = true;
                }
                else
                {
                    Console.WriteLine("Warning: unknown command '{0}'; Try -h", args[i]);
                }

            }

            if(!keySet && Params.verbose)
                Console.WriteLine("Warning: key not set using default key '1111222233334444'");
            
            if(!textSet && Params.verbose)
                Console.WriteLine("Warning: text not set using test text 'ThisIsMyText1234ThisIsMyText1234ThisIsSomeDiffec'");

            if(Params.useCBC && !initVecSet && Params.verbose)
                Console.WriteLine("Warning: useCBC set, but no initial vector set - using default initial vector '0000000000000000'");

            return true;
        }

        ///Formate byte[] to string for better readability
        public static string BytesToFormatedString(byte[] bytes, byte tabInterval = 4, byte lineInterval = 16)
        {
            string result = "";
            for(int i = 0; i < bytes.Length; i++)
            {
                if(i>0)
                {
                    if(i % lineInterval == 0)
                        result += "\n";
                    else if(i % tabInterval == 0)
                        result += "\t";
                    else
                        result += " ";
                }
                result += bytes[i].ToString("X2");
            }
            return result;
        } 
    }
}
