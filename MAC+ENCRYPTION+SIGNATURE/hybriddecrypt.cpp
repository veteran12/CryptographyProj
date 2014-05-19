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

std::map<char,int> mapp;

int main ( int argc,char *argv[] ){
    std::clock_t start,finish;
    start=clock();
    mapp['0'] = 0;
    mapp['1'] = 1;
    mapp['2'] = 2;
    mapp['3'] = 3;
    mapp['4'] = 4;
    mapp['5'] = 5;
    mapp['6'] = 6;
    mapp['7'] = 7;
    mapp['8'] = 8;
    mapp['9'] = 9;
    mapp['A'] = 10;
    mapp['B'] = 11;
    mapp['C'] = 12;
    mapp['D'] = 13;
    mapp['E'] = 14;
    mapp['F'] = 15;
    
    AutoSeededRandomPool rng;

    /* read in public key */
    string pubKey;
    string pubkeyLength;
    std::fstream fpub(argv[1],std::ios::in);
    fpub >> pubkeyLength;
    fpub >> pubKey;
    fpub.close();
    
    cout << "public key length: " << pubkeyLength <<endl;
    cout << "public key: " << pubKey <<endl;
    
    /* read in private key */
    string privKey;
    string privkeyLength;
    std::fstream fpriv(argv[2],std::ios::in);
    fpriv >> privkeyLength;
    fpriv >> privKey;
    fpriv.close();
    
    cout << "private key length: " << privkeyLength <<endl;
    cout << "private key: " << privKey <<endl;
    
    string keyciper;
    string keyciperlen;
    std::fstream fciper(argv[3],std::ios::in);
    fciper >> keyciperlen;
    fciper >> keyciper;
    
    cout << "the length of keyciper is: " << keyciperlen << endl;
    cout << "keyciper is: " << keyciper << endl;
    
    string hexcipher,timestamp,hexhash;
    fciper >> hexcipher;
    fciper >> timestamp;
    fciper >> hexhash;
    fciper.close();
    
    /* use private key to decrypt the aeskey */
    StringSource privv(privKey, true, new HexDecoder);
    RSAES_OAEP_SHA_Decryptor d(privv);
    string Hexaeskey;
    StringSource(keyciper, true,
                 new HexDecoder(
                                new PK_DecryptorFilter(rng, d,
                                                       new StringSink(Hexaeskey))));
    cout << "Hexaeskey: " << Hexaeskey << endl;
    
    /* transfer the Hexaeskey into unsigned char[] */
    unsigned char aeskey[AES::DEFAULT_KEYLENGTH];
    for( int i=0,j=0; i<AES::DEFAULT_KEYLENGTH*2; ){
        aeskey[j]=mapp[Hexaeskey[i]]*16+mapp[Hexaeskey[i+1]];
        i+=2;
        j++;
    }
    cout << "aeskey: " << aeskey << endl;
    /*for(int i=0;i<AES::DEFAULT_KEYLENGTH;i++)
	//cout << i << " " << aeskey[i] << " ";
	printf("%d: %d ", i ,aeskey[i]);
    cout << endl;*/
    
    /* transfer hexcipher to plainciper */
    string cipher;
    StringSource(hexcipher, true,
                 new HexDecoder(
                                new StringSink(cipher)
                                ) // HexEncoder
                 );
    cout << "ciper: " << cipher <<endl;
    
    /* transfer hexhash to hash */
    string hash;
    StringSource(hexhash, true,
                 new HexDecoder(
                                new StringSink(hash)
                                ) // HexEncoder
                 );
    cout << "hash: " << hash <<endl;
    
    /* varify the timestamping*/
    time_t ltime;
    time(&ltime);
    char tmp[20];
    int timestampInt = atoi(timestamp.c_str());
    cout << "the timestamp is: " << timestampInt <<endl;
    if( ltime - timestampInt < 0 || ltime - timestampInt > 6000 ){
	cout << "Woops!the timestamp verification failed!" << endl;
	exit(-1);
    }
    
    /* check mac */
    try
    {
        HMAC< SHA1 > hmac(aeskey, sizeof(aeskey));
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;
    
	string tmpcipher = cipher + timestamp;
        StringSource(tmpcipher + hash, true,
                     new HashVerificationFilter(hmac, NULL, flags)
                     ); // StringSource
    
        cout << "Verified message" << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
	cout << "error mac value!" <<endl;
        cerr << e.what() << endl;
        exit(1);
    }
    
    /* decrypt */
    string recovered;
    try
	{
	    CBC_Mode< AES >::Decryption d;
	    unsigned char ivv[AES::BLOCKSIZE]="0";
	    d.SetKeyWithIV(aeskey, sizeof(aeskey), ivv);
        
	    StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                  new StringSink(recovered)
                                                  ) // StreamTransformationFilter
                   ); // StringSource
    	cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
    
    std::fstream fplain("decryptedplaintext.txt",std::ios::out);
    fplain << recovered.length() << endl;
    fplain << recovered << endl;
    fplain.close();

    finish=clock();
    cout<< "the decryption running time is " << difftime(finish,start) << " ms" << endl;
    return 0;
}
