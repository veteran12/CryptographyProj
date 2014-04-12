//g++ encrypt.cpp -o encrypt -v -I/usr/include/cryptopp -L/Users/zhangtong/Desktop/Modern\ Cryptography/lab -lcryptopp
// ./encrypt key.txt encryptedplaintext.txt
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

#include "des.h"
using CryptoPP::DES_EDE3;

#include "modes.h"
using CryptoPP::CTR_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

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
    
    AutoSeededRandomPool prng;
    
	unsigned char key[DES_EDE3::DEFAULT_KEYLENGTH];
    
    /* generate iv */
	unsigned char iv[DES_EDE3::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
    
	string plain;
	string cipher, encoded, plainlen;
    
    //std::fstream f("key.txt",std::ios::in|std::ios::out);
    std::fstream f(argv[1],std::ios::in|std::ios::out);
    f>>encoded;
    //f<<iv;
    f.close();
    
    std::fstream fiv("iv.txt",std::ios::out);
    fiv<<iv;
    fiv.close();
    
    for(int i=0,j=0;i<DES_EDE3::DEFAULT_KEYLENGTH*2;){
        key[j]=mapp[encoded[i]]*16+mapp[encoded[i+1]];
        i+=2;
        j++;
    }
    
    cout << "key: " << encoded << endl;
    cout << "raw key: " << key << endl;
    cout << "raw iv: " << iv << endl;
    
    /*read in plaintext*/
    //std::fstream fplain("a.txt",std::ios::in);
    std::fstream fplain(argv[2],std::ios::in);
    fplain>>plainlen;
    fplain>>plain;
    fplain.close();
    cout << "plainlen: " << plainlen << endl;
    cout << "plaintext: " << plain << endl;
    
    /* encrypt */
    try
	{
		CTR_Mode< DES_EDE3 >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
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
    
    // Pretty print
	encoded.clear();
	StringSource(cipher, true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
	cout << "cipher text: " << encoded << endl;
    cout << "raw cipher text: " << cipher << endl;
    
    
    std::fstream fcipher("ciphertext.txt",std::ios::out);
    //std::fstream fcipher(argv[2],std::ios::out);
    fcipher << encoded.length() <<endl;
    fcipher<<encoded<<endl;
    fcipher.close();
    
    finish=clock();
    cout<< "the CTR-DES encrypt running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
}