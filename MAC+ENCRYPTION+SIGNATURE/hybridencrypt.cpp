#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "aes.h"
using CryptoPP::AES;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "files.h"
using CryptoPP::FileSink;

#include "aes.h"
using CryptoPP::AES;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "sha.h"
using CryptoPP::SHA1;

#include "hmac.h"
using CryptoPP::HMAC;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include <fstream>

#include <map>

#include <time.h>

int main ( int argc,char *argv[] ){
    std::clock_t start,finish;
    start=clock();
    AutoSeededRandomPool rng;

    string pubKey;
    string keyLength;
    std::fstream f(argv[1],std::ios::in);
    f >> keyLength;
    f >> pubKey;
    f.close();
    
    cout << "public key length: " << keyLength <<endl;
    cout << "public key: " << pubKey <<endl;
    
    string plain;
    string plainlen;
    std::fstream fplain(argv[2],std::ios::in);
    fplain >> plainlen;
    fplain >> plain;
    fplain.close();
    
    cout << "the length of plain is: " << plainlen << endl;
    cout << "plaint is: " << plain << endl;
    
    /* generate key for public key encryption scheme */
    unsigned char aeskey[AES::DEFAULT_KEYLENGTH];
    rng.GenerateBlock(aeskey, sizeof(aeskey));
    string encoded;
    StringSource(aeskey, sizeof(aeskey), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                )
                 );
    cout << "the Hexaeskey: " << encoded << endl;
    cout << "the aeskey: " << aeskey << endl;
    /*for(int i=0;i<AES::DEFAULT_KEYLENGTH;i++)
	//cout << i << " " << aeskey[i] << " ";
        printf("%d: %d ", i ,aeskey[i]);
    cout << endl;*/

    /* using public RSA scheme to encrypt aeskey */
    StringSource pubb(pubKey, true, new HexDecoder);
    RSAES_OAEP_SHA_Encryptor e(pubb);
    string keyciper;
    StringSource(encoded, true,
                 new PK_EncryptorFilter(rng, e,
                                        new HexEncoder(new StringSink(keyciper))));
    cout << "keyciper: " << keyciper << endl;
    
    std::fstream ciperf("ciphertext.txt",std::ios::out);
    ciperf << keyciper.length() << endl;
    ciperf << keyciper << endl;

    /* using timestamping and HMAC to deal with the massage
       first use aeskey to encrypt the massage and then add
       timestamping and MAC
    */
    
    //encrypt
    string massagecipher;
    try
	{
	    CBC_Mode< AES >::Encryption e;
	    unsigned char iv[AES::BLOCKSIZE]="0";
	    e.SetKeyWithIV(aeskey, sizeof(aeskey), iv);
        
	    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(massagecipher)
                                                ) // StreamTransformationFilter
                     ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
    
    // print
    string encoded2;
    encoded2.clear();
    StringSource(massagecipher, true,
                 new HexEncoder(
                                new StringSink(encoded2)
                                ) // HexEncoder
                 ); // StringSource
    cout << "hexadecimal massagecipher text is: " << encoded2 << endl;
    cout << "cipher text is: " << massagecipher << endl;
    ciperf << encoded2 << endl;
    
    //timestamping and mac
    time_t ltime;
    time(&ltime);
    char tmp[20];
    sprintf(tmp, "%ld",ltime);
    string s=tmp;
    cout << "the time is: " << s << endl;
    ciperf << s << endl;
    
    string mac;
    try
    {
        HMAC< SHA1 > hmac(aeskey, sizeof(aeskey));
    
        StringSource(massagecipher+s, true,
                     new HashFilter(hmac,
                                    new StringSink(mac)
                                    ) // HashFilter
                     ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    string encoded3;
    StringSource(mac, true,
                 new HexEncoder(
                                new StringSink(encoded3)
                                ) // HexEncoder
                 ); // StringSource

    cout << "hexadecimal hmac: " << encoded3 << endl;
    cout << "hmac: " << mac << endl;
    ciperf << encoded3 << endl;
    
    ciperf.close();

    finish=clock();
    cout<< "the encryption running time is " << difftime(finish,start) << " ms" << endl;
    return 0;
}
