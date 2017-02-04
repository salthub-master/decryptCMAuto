using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace decryptCMAuto
{
    /*
     * Main program itself - this contains all of the code that gets the decKey + the IV and does lots of other things.
     */
    class Program
    {
        //This code handles all of the main duties in decryptCMAuto.
        Program(string file)
        {
            Console.Write("> Loading Cookie Muncher Stub...");
            ModuleDefMD moduleDef = ModuleDefMD.Load(file); //load the stub
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK");
            Console.ForegroundColor = ConsoleColor.Gray;
            if (moduleDef.Resources.FindEmbeddedResource("source") != null) //If "source" exists, then SombraCrypt was used in the stub.
            {
                Console.Write("> Detected SombraCrypt, unpacking...");
                moduleDef = decryptCMSombraUnpack.UnpackSombra(moduleDef); //Unpack SombraCrypt.
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("OK");
                Console.ForegroundColor = ConsoleColor.Gray;
            }
            //Declare variables.
            TypeDef CookieWork = null;
            TypeDef WhiteList = null;
            string HWIDKey = "";
            string EncUserEmail = "";
            string EncCMEmail = "";
            string EncCMPass = "";
            byte[] IV = new byte[decryptCMOffsets.IV_AMOUNT]; //as of right now, the IV is 16 bytes long.
            foreach (TypeDef type in moduleDef.GetTypes())
            {
                //Lazy code, just gets classes that we need.
                if (type.Name == "cookiework") CookieWork = type;
                else if (type.Name == "whitelist") WhiteList = type;
                else if (type.Name == "encryption")
                {
                    CookieMuncherOriginal(moduleDef); //If this class exists, we have a Cookie Muncher Original stub.
                    return;
                }
            }
            Console.Write("> Getting IV's/Keys...");
            if (CookieWork == null || WhiteList == null) //If the classes dont exist, then this isnt a CMR5 stub.
            {
                Console.WriteLine("ERROR: Invalid stub! (failed to find cookiework/whitelist)");
                Console.ReadLine();
                Environment.Exit(0);
            }
            foreach (MethodDef method in CookieWork.Methods)
            {
                if (method.Name == ".ctor") //NOTE: .ctor internally is used to represent constructors for classes. This also means that the users decKey (their HWID) is also in there!
                {
                    HWIDKey = (string) method.Body.Instructions[decryptCMOffsets.OFFSET_HWIDKEY].Operand; //Get decKey.
                }
                else if (method.Name == "exec") //Contains the actual encrypted information itself.
                {
                    EncCMEmail = (string) method.Body.Instructions[decryptCMOffsets.OFFSET_CMEMAIL].Operand;
                    EncCMPass = (string) method.Body.Instructions[decryptCMOffsets.OFFSET_CMPASS].Operand;
                    EncUserEmail = (string) method.Body.Instructions[decryptCMOffsets.OFFSET_USEREMAIL].Operand;
                }
            }
            if (String.IsNullOrEmpty(HWIDKey) || String.IsNullOrEmpty(EncCMEmail) || String.IsNullOrEmpty(EncCMPass) || String.IsNullOrEmpty(EncUserEmail))
            {
                //We dont have one of the right keys/encrypted things - error out.
                Console.WriteLine("ERROR: Invalid stub! (failed to find HWIDKey/EncKeys)");
                Console.ReadLine();
                Environment.Exit(0);
            }
            foreach (MethodDef method in WhiteList.Methods)
            {
                if (method.Name == "init2") //Used in CMR5 to declare the IV.
                {
                    int counter = 0;
                    int counterIns = decryptCMOffsets.OFFSET_IVINITAL;
                    while (counter < 16)
                    {
                        /*
                         * This is complicated IL crap, but you should be able to understand.
                         * In this particular malware, each IV byte was ALWAYS 4 instructions away from the last one. Luckily, this means we didnt have to code the offsets indivdually.
                         */
                        IV[counter] =
                            Convert.ToByte(method.Body.Instructions[counterIns + counter * decryptCMOffsets.OFFSET_IVBETWEEN]
                                .GetLdcI4Value()); //Errors arise if we just use .Operand
                        counter++;
                    }
                }
            }
            //Print out results - we are done!
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            decryptCMToolchain chainDec = new decryptCMToolchain(IV, HWIDKey); //Init toolchain decryptor.
            Console.Write("User Email: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(chainDec.decryptCM_decrypt(EncUserEmail)); //decrypt (user email)
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Cookie Muncher Email: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(chainDec.decryptCM_decrypt(EncCMEmail)); //decrypt (cmr5 author email)
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Cookie Muncher Email (Password): ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(chainDec.decryptCM_decrypt(EncCMPass)); //decrypt (cmr5 author password)
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        //This handles decryption for ORIGINAL CMR5 stubs.
        void CookieMuncherOriginal(ModuleDefMD moduleDef)
        {
            Console.Write("> Detected Cookie Muncher Original, getting IV/Keys...");
            //Declare variables.
            TypeDef Encryption = null;
            TypeDef Module1 = null;
            string HWIDKey = "";
            string EncUserEmail = "";
            string EncCMCombo = "";
            byte[] IV = new byte[decryptCMOffsets.IV_AMOUNT];
            foreach (TypeDef type in moduleDef.GetTypes())
            {
                //Lazy code, just gets classes that we need.
                if (type.Name == "encryption") Encryption = type;
                else if (type.Name == "Module1") Module1 = type;
            }
            if (Encryption == null || Module1 == null)
            {
                Console.WriteLine("ERROR: Invalid stub! (failed to find encryption/Module1)");
                Console.ReadLine();
                Environment.Exit(0);
            }
            foreach (MethodDef method in Encryption.Methods)
            {
                if (method.Name == ".ctor")  //NOTE: .ctor internally is used to represent constructors for classes. This also means that the users decKey (their HWID) is also in there!
                {
                    HWIDKey = (string)method.Body.Instructions[decryptCMOffsets.COFFSET_HWIDKEY].Operand;
                }
                else if (method.Name == "init") //Used in CMR5 to declare the IV.
                {
                    int counter = 0;
                    int counterIns = decryptCMOffsets.COFFSET_IVINITAL;
                    while (counter < 16)
                    {
                        /*
                         * This is complicated IL crap, but you should be able to understand.
                         * In this particular malware, each IV byte was ALWAYS 4 instructions away from the last one. Luckily, this means we didnt have to code the offsets indivdually.
                         */
                        IV[counter] =
                            Convert.ToByte(method.Body.Instructions[counterIns + counter * decryptCMOffsets.OFFSET_IVBETWEEN]
                                .GetLdcI4Value()); //Errors arise if we just use .Operand
                        counter++;
                    }
                }
            }
            if (String.IsNullOrEmpty(HWIDKey)) //If we dont have the HWIDKey yet, then this isnt a CMR5 stub.
            {
                Console.WriteLine("ERROR: Invalid stub! (failed to find HWIDKey)");
                Console.ReadLine();
                Environment.Exit(0);
            }
            foreach (MethodDef method in Module1.Methods)
            {
                if (method.Name == "Main") //Contains the actual encrypted information itself.
                {
                    EncUserEmail = (string) method.Body.Instructions[decryptCMOffsets.COFFSET_USEREMAIL].Operand;
                    EncCMCombo = (string) method.Body.Instructions[decryptCMOffsets.COFFSET_CMDOUBLE].Operand;
                }
            }
            //Print out results - we are done!
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            decryptCMToolchain chainDec = new decryptCMToolchain(IV, HWIDKey); //Init toolchain decryptor.
            Console.Write("User Email: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(chainDec.decryptCM_decrypt(EncUserEmail)); //decrypt (user email)
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Cookie Muncher Email: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(chainDec.decryptCM_decrypt(EncCMCombo)); //decryt (cookie muncher email)
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        static void Main(string[] args)
        {
            Console.Title = "decryptCMAuto v1.1.0 - by 3dsboy08";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("       _                            _    _____ __  __ \r\n     | |                          | |  / ____|  \\/  |\r\n   __| | ___  ___ _ __ _   _ _ __ | |_| |    | \\  / |\r\n  / _` |/ _ \\/ __| \'__| | | | \'_ \\| __| |    | |\\/| |\r\n | (_| |  __/ (__| |  | |_| | |_) | |_| |____| |  | |\r\n  \\__,_|\\___|\\___|_|   \\__, | .__/ \\__|\\_____|_|  |_|\r\n                        __/ | |                      \r\n                       |___/|_|                      \n\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            if (args.Length != 1) //Check if file was passed into args.
            {
                Console.WriteLine("ERROR: No file specified/too many args!");
                Console.ReadLine();
                Environment.Exit(0);
            }
            if (!File.Exists(args[0])) //Check if file exists.
            {
                Console.WriteLine("ERROR: Invalid file!");
                Console.ReadLine();
                Environment.Exit(0);
            }
            new Program(args[0]);
            Console.ReadLine();
        }
    }
}
