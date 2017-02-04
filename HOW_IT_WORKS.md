# How decryptCMAuto works.

decryptCMAuto internally uses some major flaws inside of the Cookie Muncher V5 encryption for emails/passwords.

**The encryption key used is the HWID of the user whitelisted for the program**:
When reverse engineering a Cookie Muncher V5 stub - I found a pretty stupid (but funny) vulnerability. The AES encryption key is just the whitelisted users HWID - this also results that getting a stub from someone else can allow you to steal their whitelist for Cookie Muncher V5.

**All stubs send a email from one email address**:
Again - another stupid design decision from Cookie Muncher creators. All stubs send a email to the creator of the stub from one email address:

    Username: cmr5service3@gmail.com
    Password: itsmyparty123
    
Luckily, this was shut down shortly after the first version of decryptCMAuto was released.

**SombraCrypt used a static AES key**:

"SombraCrypt" - a scantime crypter included with Cookie Muncher V5 - used a static encryption key  (`n792fjkl`) inside of its stubs. A static IV is also used inside SombraCrypt, allowing us to decrypt it without much effort.

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

