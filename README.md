# Crypto++ Sample Application

CryptoppStaticLibraryUsageSample has the following samples

```c
void sha1Operation(void);
void sha256Operation(void);
void sha512Operation(void);
int aesOperation(void);
void desOperation(void);
void hmacSha1Operation(void);
void hmacSha256Operation(void);
void crcOperation(void);
void md5Operation(void);
```

Also includes following utilies

```c
std::string bin2hex(const std::string& input)
void printBinHex(char* title, const void* data, size_t size)
void printBinHexAscii(char* title, const void* data, size_t size)
string secByteBlockToHex(SecByteBlock byteBlock)
string byteBlockToHex(unsigned char* data, size_t length)
```

# Compile Crypto++ Library

Open Crypto++ Solution and Compile `cryptlib` project to generate static library file with `Debug ` or `Release`with `Win32 `settings

```batch
../cryptopp850/cryptest.sln
```

Your output will be located at

```batch
..\cryptopp850\Win32\Output\Debug\cryptlib.lib
```

# Compile and Run Sample Application

Open crypto test application

```batch
../CryptoppTestApplication/CryptoppTestApplication.sln
```

All static library path configurations are placed `in CryptoppStaticLibraryUsageSample.cpp` file as follow, check static library path is correct for your solution. Path is relative. 

```c
#ifdef _DEBUG
#pragma comment(lib, "../../cryptopp850/Win32/Output/Debug/cryptlib.lib")
#else
#pragma comment(lib, "../../cryptopp850/Win32/Output/Release/cryptlib.lib") 
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "../../cryptopp850/cryptlib.h"
#include "../../cryptopp850/sha.h"
#include "../../cryptopp850/hex.h"
#include "../../cryptopp850/files.h"
#include "../../cryptopp850/rijndael.h"
#include "../../cryptopp850/modes.h"
#include "../../cryptopp850/osrng.h"
#include "../../cryptopp850/md5.h"
#include "../../cryptopp850/crc.h"
#include "../../cryptopp850/des.h"

#include <iostream>
#include <string>

using namespace std;
using namespace CryptoPP;
```

if you run application you will have the following output

```batch
Sender Name: SHA-1
Sender Digest size: 20
Sender Block size: 64
Sender Message: Yoda said, Do or do not. There is no try.
Sender Message Digest: 05C0042DF9A7793B7BDE3AB9724C08CF37398652
Verified hash over message:[05C0042DF9A7793B7BDE3AB9724C08CF37398652]
Verified hash over message
Sender Name: SHA-256
Sender Digest size: 32
Sender Block size: 64
Sender Message: Yoda said, Do or do not. There is no try.
Sender Message Digest: F00E3F70A268FBA990296B32FF2B6CE7A0757F31EC3059B13D3DB1E60D9E885C
Verified hash over message:[F00E3F70A268FBA990296B32FF2B6CE7A0757F31EC3059B13D3DB1E60D9E885C]
Verified hash over message
Sender Name: SHA-512
Sender Digest size: 64
Sender Block size: 128
Sender Message: Yoda said, Do or do not. There is no try.
Sender Message Digest: 51693F901D5318B542E4D788AD38611BF374CBCD0FDEB4A913167A29AF89D4530EA9848ADBF4C671B720C64882EBB9A3347CFF74657BF8FF07F07C9CD93E57D3
Verified hash over message:[51693F901D5318B542E4D788AD38611BF374CBCD0FDEB4A913167A29AF89D4530EA9848ADBF4C671B720C64882EBB9A3347CFF74657BF8FF07F07C9CD93E57D3]
Verified hash over message
plain text: CBC Mode Test
plain text hex: 434243204D6F64652054657374
key: 66861830A0EC3DC762E49A1A65546CB1
iv: 6D64593E2EF14A40A8678B29FF11B272
cipher text: 839F7901FAEF38BEB0355E4C6D3738A986AA825E4BDDD7E9EAB69A454B3B0A62
recovered text: 434243204D6F6465205465737400000000000000000000000000000000000000
CBC Mode Test
original text: ++++++++--------********////////
Encrypt: ♥       4÷â▒-'Ë♣À▬d¢▬********////////
Decrypt: ++++++++--------********////////
Message: 05080C0E010E06000101010101010101060406010704060100000000
Digest: 0EA5E034142BDECC5D3AEC9DE727EE836BF95E1D
Message: 05080C0E010E06000101010101010101060406010704060100000000
Digest: B37D2083993078565E69E73A7043B4EF48BDC7D3B3B8FB1FEE743F2C46A7946A
Message: Yoda said, Do or do not. There is no try.
Digest: 1FE93886
Message: Yoda said, Do or do not. There is no try.
Digest: CF4A16604182539B5CE297092A034625
```

Good luck.
