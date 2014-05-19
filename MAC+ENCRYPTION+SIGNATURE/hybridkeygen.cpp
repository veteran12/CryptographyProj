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

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "files.h"
using CryptoPP::FileSink;

//AutoSeededRandomPool rng;
//RSAES_OAEP_SHA_Decryptor priv( (rng), 1024);

int main ( int argc,char *argv[] ){
    std::clock_t start,finish;
    start=clock();
    AutoSeededRandomPool rng;
    
    string privKey;
    RSAES_OAEP_SHA_Decryptor priv( (rng), 1024);
    //priv( (rng), 1024);
    HexEncoder privStr(new StringSink(privKey));
    priv.DEREncode(privStr);
    privStr.MessageEnd();
    cout << "private key: " << privKey << endl;
    std::fstream fpriv("secretkey.txt",std::ios::out);
    fpriv << privKey.length() << endl;
    fpriv << privKey << endl;
    fpriv.close();
	
    string pubKey;
    RSAES_OAEP_SHA_Encryptor pub(priv);
    HexEncoder pubStr(new StringSink(pubKey));
	pub.DEREncode(pubStr);
	pubStr.MessageEnd();
    cout << "public key: " << pubKey << endl;
    
    std::fstream fpub("publickey.txt",std::ios::out);
    fpub << pubKey.length() << endl;
    fpub << pubKey << endl;
    fpub.close();
    /*string message = "hey yo";
    StringSource pubb(pubKey, true, new HexDecoder);
    RSAES_OAEP_SHA_Encryptor e(pubb);
	string ciper;
	StringSource(message, true,
                 new PK_EncryptorFilter(rng, e,
                                        new HexEncoder(new StringSink(ciper))));
    cout << "ciper: " << ciper << endl;
    
    StringSource privv(privKey, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor d(privv);
	string plain;
	StringSource(ciper, true,
                 new HexDecoder(
                                new PK_DecryptorFilter(rng, d,
                                                       new StringSink(plain))));
    cout << "plaintext: " << plain << endl;*/
    finish=clock();
    cout<< "the keygen running time is " << difftime(finish,start) << " ms" << endl;
    return 0;
}
