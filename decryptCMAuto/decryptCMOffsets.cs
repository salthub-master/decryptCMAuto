using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace decryptCMAuto
{
    /*
     * This class is just a storage class for decryptCMAuto offsets - dont touch unless if a CMR5 update is pushed that breaks it.
     */
    static class decryptCMOffsets
    {
        //Current known Cookie Muncher Pro Offsets
        public static int OFFSET_HWIDKEY = 6;
        public static int OFFSET_USEREMAIL = 73;
        public static int OFFSET_CMEMAIL = 57;
        public static int OFFSET_CMPASS = 63;
        public static int OFFSET_IVINITAL = 52;

        //Current known Cookie Muncher Original Offsets
        public static int COFFSET_HWIDKEY = 3;
        public static int COFFSET_IVINITAL = 53;
        public static int COFFSET_USEREMAIL = 74;
        public static int COFFSET_CMDOUBLE = 55;

        //Offsets are same between both
        public static int OFFSET_IVBETWEEN = 4;
        public static int IV_AMOUNT = 16;
    }
}
