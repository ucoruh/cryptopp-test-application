// CryptoppTestApplication.cpp : This file contains the 'main' function. Program execution begins and ends there.

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

//Utilities
string bin2hex(const string& inBinaryString);
void hex2bin(const string inHexString, char* outBinaryData, int& outBinaryDataLength);
void printBinHex(char* title, const void* data, size_t size);
void printBinHexAscii(char* title, const void* data, size_t size);
string secByteBlockToHex(SecByteBlock byteBlock);
string byteBlockToHex(unsigned char* data, size_t length);

//Sample Operation Usages
void sha1Operation(void);
void sha256Operation(void);
void sha512Operation(void);
int aesOperation(void);
void desOperation(void);
void DES_Process(const char* keyString, byte* block, size_t length, CryptoPP::CipherDir direction);
void hmacSha1Operation(void);
void hmacSha256Operation(void);
void crcOperation(void);
void md5Operation(void);

int main()
{

     sha1Operation();
     sha256Operation();
     sha512Operation();
     
     if (aesOperation() != 0)
         exit(-1);

     desOperation();
     hmacSha1Operation();
     hmacSha256Operation();
     crcOperation();
     md5Operation();

    system("PAUSE");

    return 0;
}

#pragma region Utilities

std::string bin2hex(const std::string& input)
{
    std::string res;
    const char hex[] = "0123456789ABCDEF";
    for (auto sc : input)
    {
        unsigned char c = static_cast<unsigned char>(sc);
        res += hex[c >> 4];
        res += hex[c & 0xf];
    }

    return res;
}

void printBinHex(char* title, const void* data, size_t size) {
    const unsigned char* buf = static_cast<const unsigned char*>(data);
    printf("[%s] [%zu]\n", title, size);
    printf("-------------------------------\n");
    for (size_t i = 0; i < size; i++) {
        printf("%.2X ", buf[i] & 0xFF);
        if (i && !((i + 1) % 16)) printf("\n");
    }
    if (size % 16) printf("\n");
    printf("-------------------------------\n");
}
/**
 * Source : https://gist.github.com/ccbrown/9722406
 */
void printBinHexAscii(char* title, const void* data, size_t size) {
    char ascii[17];
    ascii[16] = '\0';
    printf("[%s] [%zu]\n", title, size);
    printf("-------------------------------\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        }
        else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (size_t j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    if (size % 16) printf("\n");
    printf("-------------------------------\n");
}

string secByteBlockToHex(SecByteBlock byteBlock)
{
    string encoded;

    StringSource ss(byteBlock, byteBlock.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

    return encoded;
}

string byteBlockToHex(unsigned char* data, size_t length)
{
    string encoded;

    StringSource ss(data, length, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

    return encoded;
}

#pragma endregion

#pragma region Example Usages
void sha1Operation(void)
{
    HexEncoder encoder(new FileSink(std::cout));

    SHA1 hashSender;

    std::cout << "Sender Name: " << hashSender.AlgorithmName() << std::endl;
    std::cout << "Sender Digest size: " << hashSender.DigestSize() << std::endl;
    std::cout << "Sender Block size: " << hashSender.BlockSize() << std::endl;

    //Sample Message for SHA-1
    std::string senderMessageString = "Yoda said, Do or do not. There is no try.";
    std::string senderMessageDigest;

    //SENDER ---------------------------------------------
    hashSender.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    senderMessageDigest.resize(hashSender.DigestSize());
    hashSender.Final((byte*)&senderMessageDigest[0]);

    std::cout << "Sender Message: " << senderMessageString << std::endl;

    std::cout << "Sender Message Digest: ";
    StringSource(senderMessageDigest, true, new Redirector(encoder));
    std::cout << std::endl;
    //SENDER ---------------------------------------------

    //RECEIVER -------------------------------------------
    SHA1 hashReceiver;
    hashReceiver.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    bool verified = hashReceiver.Verify((const byte*)senderMessageDigest.data());

    std::string hexDigest = bin2hex(senderMessageDigest);
    std::cout << "Verified hash over message:[" << hexDigest << "]" << std::endl;

    if (verified == true)
        std::cout << "Verified hash over message" << std::endl;
    else
        std::cout << "Failed to verify hash over message" << std::endl;
    //RECEIVER ---------------------------------------------
}

void sha256Operation(void)
{
    HexEncoder encoder(new FileSink(std::cout));

    SHA256 hashSender;

    std::cout << "Sender Name: " << hashSender.AlgorithmName() << std::endl;
    std::cout << "Sender Digest size: " << hashSender.DigestSize() << std::endl;
    std::cout << "Sender Block size: " << hashSender.BlockSize() << std::endl;

    //Sample Message for SHA-1
    std::string senderMessageString = "Yoda said, Do or do not. There is no try.";
    std::string senderMessageDigest;

    //SENDER ---------------------------------------------
    hashSender.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    senderMessageDigest.resize(hashSender.DigestSize());
    hashSender.Final((byte*)&senderMessageDigest[0]);

    std::cout << "Sender Message: " << senderMessageString << std::endl;

    std::cout << "Sender Message Digest: ";
    StringSource(senderMessageDigest, true, new Redirector(encoder));
    std::cout << std::endl;
    //SENDER ---------------------------------------------

    //RECEIVER -------------------------------------------
    SHA256 hashReceiver;
    hashReceiver.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    bool verified = hashReceiver.Verify((const byte*)senderMessageDigest.data());

    std::string hexDigest = bin2hex(senderMessageDigest);
    std::cout << "Verified hash over message:[" << hexDigest << "]" << std::endl;

    if (verified == true)
        std::cout << "Verified hash over message" << std::endl;
    else
        std::cout << "Failed to verify hash over message" << std::endl;
    //RECEIVER ---------------------------------------------
}

void sha512Operation(void)
{
    HexEncoder encoder(new FileSink(std::cout));

    SHA512 hashSender;

    std::cout << "Sender Name: " << hashSender.AlgorithmName() << std::endl;
    std::cout << "Sender Digest size: " << hashSender.DigestSize() << std::endl;
    std::cout << "Sender Block size: " << hashSender.BlockSize() << std::endl;

    //Sample Message for SHA-1
    std::string senderMessageString = "Yoda said, Do or do not. There is no try.";
    std::string senderMessageDigest;

    //SENDER ---------------------------------------------
    hashSender.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    senderMessageDigest.resize(hashSender.DigestSize());
    hashSender.Final((byte*)&senderMessageDigest[0]);

    std::cout << "Sender Message: " << senderMessageString << std::endl;

    std::cout << "Sender Message Digest: ";
    StringSource(senderMessageDigest, true, new Redirector(encoder));
    std::cout << std::endl;
    //SENDER ---------------------------------------------

    //RECEIVER -------------------------------------------
    SHA512 hashReceiver;
    hashReceiver.Update((const byte*)senderMessageString.data(), senderMessageString.size());
    bool verified = hashReceiver.Verify((const byte*)senderMessageDigest.data());

    std::string hexDigest = bin2hex(senderMessageDigest);
    std::cout << "Verified hash over message:[" << hexDigest << "]" << std::endl;

    if (verified == true)
        std::cout << "Verified hash over message" << std::endl;
    else
        std::cout << "Failed to verify hash over message" << std::endl;
    //RECEIVER ---------------------------------------------
}

int aesOperation(void)
{
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plain = "CBC Mode Test"; //13+3 = 16 (32,48,...)
    std::string cipher, recovered;

    std::cout << "plain text: " << plain << std::endl;

    std::cout << "plain text hex: ";
    encoder.Put((const byte*)&plain[0], plain.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    SecByteBlock cipherBuffer(0, AES::BLOCKSIZE * 2); //32 bytes
    SecByteBlock plainBuffer(0, AES::BLOCKSIZE * 2); //32 bytes

    memcpy(plainBuffer, plain.data(), plain.size()); //Padding...

    try
    {

    // Encryption -----------------------------------------------
    CBC_Mode<AES>::Encryption e(key, key.size(), iv);

    e.ProcessData(cipherBuffer, plainBuffer, plainBuffer.size());

    std::cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipherBuffer[0], cipherBuffer.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Decryption  -----------------------------------------------
    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    SecByteBlock newplainBuffer(0, AES::BLOCKSIZE * 2); //32 bytes

    d.ProcessData(newplainBuffer, cipherBuffer, cipherBuffer.size());

    std::cout << "recovered text: ";
    encoder.Put((const byte*)&newplainBuffer[0], newplainBuffer.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::string s(reinterpret_cast<char*>(newplainBuffer.BytePtr()), newplainBuffer.size());
    std::cout << s << std::endl;

    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}

void desOperation(void)
{

    byte block[1024] = "++++++++--------********////////";

    const char* key = "http://qsanguosha.org/forum";

    printf("original text: %s\n", block);

    DES_Process(key, block, 16, CryptoPP::ENCRYPTION);

    printf("Encrypt: %s\n", block);

    DES_Process(key, block, 16, CryptoPP::DECRYPTION);

    printf("Decrypt: %s\n", block);
}

void DES_Process(const char* keyString, byte* block, size_t length, CryptoPP::CipherDir direction) {
    using namespace CryptoPP;

    byte key[DES_EDE2::KEYLENGTH];
    memcpy(key, keyString, DES_EDE2::KEYLENGTH);
    BlockTransformation* t = NULL;

    if (direction == ENCRYPTION)
        t = new DES_EDE2_Encryption(key, DES_EDE2::KEYLENGTH);
    else
        t = new DES_EDE2_Decryption(key, DES_EDE2::KEYLENGTH);

    int steps = length / t->BlockSize();
    for (int i = 0; i < steps; i++) {
        int offset = i * t->BlockSize();
        t->ProcessBlock(block + offset);
    }

    delete t;
}

void hmacSha1Operation(void)
{
    const byte m[] = {
  0x5,0x8,0xC,0xE,0x1,0xE,0x6,0x0,0x1,0x1,
  0x1,0x1,0x1,0x1,0x1,0x1,0x6,0x4,0x6,0x1,
  0x7,0x4,0x6,0x1,0x0,0x0,0x0,0x0
    };

    const byte k[] = {
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1
    };

    HexEncoder hex(new FileSink(std::cout));

    HMAC<SHA1> hmac(k, sizeof(k));
    hmac.Update(m, sizeof(m));

    byte d[HMAC<SHA1>::DIGESTSIZE];
    hmac.Final(d);

    std::cout << "Message: ";
    hex.Put(m, sizeof(m));
    hex.MessageEnd();
    std::cout << std::endl;

    std::cout << "Digest: ";
    hex.Put(d, sizeof(d));
    hex.MessageEnd();
    std::cout << std::endl;
}

void hmacSha256Operation(void)
{
    const byte m[] = {
  0x5,0x8,0xC,0xE,0x1,0xE,0x6,0x0,0x1,0x1,
  0x1,0x1,0x1,0x1,0x1,0x1,0x6,0x4,0x6,0x1,
  0x7,0x4,0x6,0x1,0x0,0x0,0x0,0x0
    };

    const byte k[] = {
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1
    };

    HexEncoder hex(new FileSink(std::cout));

    HMAC<SHA256> hmac(k, sizeof(k));
    hmac.Update(m, sizeof(m));

    byte d[HMAC<SHA256>::DIGESTSIZE];
    hmac.Final(d);

    std::cout << "Message: ";
    hex.Put(m, sizeof(m));
    hex.MessageEnd();
    std::cout << std::endl;

    std::cout << "Digest: ";
    hex.Put(d, sizeof(d));
    hex.MessageEnd();
    std::cout << std::endl;
}

void crcOperation(void) {

    HexEncoder encoder(new FileSink(std::cout));

    std::string msg = "Yoda said, Do or do not. There is no try.";
    std::string digest;

    CRC32C crc;
    crc.Update((const byte*)&msg[0], msg.size());
    digest.resize(crc.DigestSize());
    crc.Final((byte*)&digest[0]);

    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: ";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;
}

void md5Operation(void) {

    HexEncoder encoder(new FileSink(std::cout));

    string msg = "Yoda said, Do or do not. There is no try.";
    string digest;

    Weak::MD5 hash;
    hash.Update((const byte*)&msg[0], msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: ";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;

}

#pragma endregion

