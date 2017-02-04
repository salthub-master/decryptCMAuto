using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.IO;

namespace decryptCMAuto
{
    /*
     * Luckily for us, SombraCrypt was very poorly coded. It seems to just be a (very) crappy scantime "crypter" - wouldnt even call it that.
     * It didnt really do much to improve CMR5's blatent AV scores, making it useless.
     */
    public static class decryptCMSombraUnpack
    {
        //From http://stackoverflow.com/questions/221925/creating-a-byte-array-from-a-stream - very useful
        public static byte[] ReadFully(IImageStream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        //SombraCrypt encoded data is just stored in a resource named "source" - not really that creative.
        public static ModuleDefMD UnpackSombra(ModuleDefMD packed)
        {
            IImageStream sourceStream = packed.Resources.FindEmbeddedResource("source").Data;
            byte[] encData = ReadFully(sourceStream);
            InitFake();
            return ModuleDefMD.Load(DecryptSombraData(encData));
        }

        //Initiate decryption algorithm - seems to just be AES. Copy + pasted from a SombraCrypt stub.
        public static void InitFake()
        {
            byte[] rgbKey = Encoding.UTF8.GetBytes("n792fjkl"); //Decryption key used internally by SombraCrypt
            byte[] rgbIV =
            {
                234,
                12,
                52,
                44,
                214,
                222,
                200,
                109,
                2,
                98,
                45,
                76,
                88,
                53,
                23,
                78
            };
            RijndaelManaged rijndaelManaged = new RijndaelManaged {Mode = CipherMode.CBC};
            decryptor = rijndaelManaged.CreateDecryptor(rgbKey, rgbIV);
        }

        //Decryption algo. itself.
        public static byte[] DecryptSombraData(byte[] array)
        {
            byte[] result;
            try
            {
                MemoryStream memoryStream = new MemoryStream(array);
                CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                cryptoStream.Read(array, 0, array.Length);
                memoryStream.Close();
                cryptoStream.Close();
                result = array;
            }
            catch (Exception)
            {
                return null;
            }
            return result;
        }

        private static ICryptoTransform decryptor;
    }
}
