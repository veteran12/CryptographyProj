#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <time.h>
using std::time_t;

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
    
    /* generate iv */
   // AutoSeededRandomPool prng;
    //unsigned char iv[AES::BLOCKSIZE];
    //prng.GenerateBlock(iv, sizeof(iv));
    //memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    /*std::fstream fiv("iv.txt",std::ios::out);
     fiv<<iv;
     fiv.close();
     cout << "iv is: " << iv << endl;*/
    
    string encoded1,encoded2,mac,plain,plainlen,cipher;
    
    encoded1.clear();
    encoded2.clear();
    
    std::fstream f(argv[1],std::ios::in);
    f>>encoded1;
    f>>encoded2;
    f.close();
    
    /* read in keys */
    for(int i=0,j=0;i<16*2;){
        key1[j]=mapp[encoded1[i]]*16+mapp[encoded1[i+1]];
        i+=2;
        j++;
    }
    cout << "hexadecimal key for mac is: " << encoded1 << endl;

    
    for(int i=0,j=0;i<AES::DEFAULT_KEYLENGTH*2;){
        key2[j]=mapp[encoded2[i]]*16+mapp[encoded2[i+1]];
        i+=2;
        j++;
    }
    cout << "hexadecimal key for encrypt: " << encoded2 << endl;
  
    
    /*read in plaintext*/
    std::fstream fplain(argv[2],std::ios::in);
    fplain>>plainlen;
    fplain>>plain;
    fplain.close();
    cout << "the length of plain is: " << plainlen << endl;
    cout << "plaint is: " << plain << endl;
    
    /* encrypt */
    try
	{
	    CBC_Mode< AES >::Encryption e;
	    unsigned char ivv[AES::BLOCKSIZE]="0";
	    e.SetKeyWithIV(key2, sizeof(key2), ivv);
        
	    StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)
                                                    ) // StreamTransformationFilter
                     ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
    
    // print
    encoded2.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                                new StringSink(encoded2)
                                ) // HexEncoder
                 ); // StringSource
    cout << "hexadecimal cipher text is: " << encoded2 << endl;
    cout << "cipher text is: " << cipher << endl;
    
    time_t ltime;
    time(&ltime);
    char tmp[20];
    sprintf(tmp, "%ld",ltime);
    string s=tmp;
    cout << "the time is: " << s << endl;
    
    try
    {
        CBC_MAC< CryptoPP::AES > cbcmac(key1, sizeof(key1));
        
        StringSource(cipher+s, true,
                     new HashFilter(cbcmac,
                                    new StringSink(mac)
                                    ) // HashFilter
                     ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    encoded1.clear();
    StringSource(mac, true,
                 new HexEncoder(
                                new StringSink(encoded1)
                                ) // HexEncoder
                 ); // StringSource
    
    cout << "hexadecimal cbcmac: " << encoded1 << endl;
    cout << "cbcmac: " << mac << endl;
    
    std::fstream fcipher("ciphertext.txt",std::ios::out);
    fcipher << encoded2.length() <<endl;
    fcipher << s << endl;
    fcipher << encoded1 << endl;
    fcipher << encoded2 <<endl;
    fcipher.close();
	
    finish=clock();
    cout<< "the encrypto running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
    
}