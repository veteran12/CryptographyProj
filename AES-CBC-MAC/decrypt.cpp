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

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "secblock.h"
using CryptoPP::SecByteBlock;


#include "cbcmac.h"
using CryptoPP::CBC_MAC;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include <fstream>

#include <map>

#include <time.h>

std::map<char,int> mapp;

int main(int argc, char* argv[])
{
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
    mapp['a'] = 10;
    mapp['b'] = 11;
    mapp['c'] = 12;
    mapp['d'] = 13;
    mapp['e'] = 14;
    mapp['f'] = 15;
    
    //SecByteBlock key1(16);
    //SecByteBlock key2(AES::DEFAULT_KEYLENGTH);
    unsigned char key1[16];
    unsigned char key2[AES::DEFAULT_KEYLENGTH];
   // unsigned char iv[AES::BLOCKSIZE];
    //memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    
    string encoded1,encoded2,hash,cipherlen,cipher,hexcipher,hexhash,recovered,timestamp;
    
    /* read in keys */
    std::fstream f(argv[1],std::ios::in|std::ios::out);
    f >> encoded1;
    f >> encoded2;
    f.close();
    
    for(int i=0,j=0;i<16*2;){
        key1[j]=mapp[encoded1[i]]*16+mapp[encoded1[i+1]];
        i+=2;
        j++;
    }
    cout << "hexadecimal key for mac: " << encoded1 << endl;
    
    for(int i=0,j=0;i<AES::DEFAULT_KEYLENGTH*2;){
        key2[j]=mapp[encoded2[i]]*16+mapp[encoded2[i+1]];
        i+=2;
        j++;
    }
    cout << "hexadecimal key for decrypt is: " << encoded2 << endl;
    
    /*read in hashval*/
    std::fstream fcipher(argv[2],std::ios::in);
    fcipher >> cipherlen;
    fcipher >> timestamp;
    fcipher >> hexhash;
    fcipher >> hexcipher;
    fcipher.close();
    
    StringSource(hexcipher, true,
                 new HexDecoder(
                                new StringSink(cipher)
                                ) // HexEncoder
                 );
    
    StringSource(hexhash, true,
                 new HexDecoder(
                                new StringSink(hash)
                                ) // HexEncoder
                 );
    
    cout << "the length of ciphertext is: " << cipherlen << endl;
    cout << "hexhash value is: " << hexhash << endl;
    cout << "hash value is: " << hash << endl;
    cout << "hexadecimal cipher is: " << hexcipher << endl;
    cout << "cipher is: " << cipher << endl;
    
    /*std::fstream fiv("iv.txt",std::ios::in);
     fiv>>iv;
     fiv.close();
     cout << "iv is: " << iv << endl;*/
    
    /* varify */
    time_t ltime;
    time(&ltime);
    //char tmp[20];
    int timestampInt = atoi(timestamp.c_str());
    cout << "the timestamp is: " << timestampInt <<endl;
    if( ltime - timestampInt < 0 || ltime - timestampInt > 600 ){
        cout << "Woops!the timestamp verification failed!" << endl;
        exit(-1);
    }
    
    try
    {
        CBC_MAC< CryptoPP::AES > cbcmac(key1, sizeof(key1));
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;
        
        string tmpcipher = cipher + timestamp;
        StringSource(tmpcipher + hash, true,
                     new HashVerificationFilter(cbcmac, NULL, flags)
                     ); // StringSource
        
        cout << "Verified message" << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        cout << "error mac value!" <<endl;
        cerr << e.what() << endl;
        exit(1);
    }
    
    try
	{
	    CBC_Mode< AES >::Decryption d;
	    unsigned char ivv[AES::BLOCKSIZE]="0";
	    d.SetKeyWithIV(key2, sizeof(key2), ivv);
        
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
	fplain<<recovered.length()<<endl;
	fplain<<recovered<<endl;
	fplain.close();
    
    finish=clock();
    cout<< "the decrypt running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
}