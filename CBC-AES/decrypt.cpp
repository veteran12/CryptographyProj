//g++ decrypt.cpp -o decrypt -v -I/usr/include/cryptopp -L/Users/zhangtong/Desktop/Modern\ Cryptography/lab -lcryptopp
//./decrypt key.txt ciphertext.txt 
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

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

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
    
	unsigned char key[AES::DEFAULT_KEYLENGTH];
    unsigned char iv[AES::BLOCKSIZE];
    
	string plain;
	string cipher, encoded, recovered, hexcipher, cipherlen;
    
	encoded.clear();
    
    std::fstream f(argv[1],std::ios::in);
    f>>encoded;
    //f>>iv;
    f.close();
    
    std::fstream fiv("iv.txt",std::ios::in);
    fiv>>iv;
    fiv.close();
    
    /* read in keys */
    for(int i=0,j=0;i<AES::DEFAULT_KEYLENGTH*2;){
        key[j]=mapp[encoded[i]]*16+mapp[encoded[i+1]];
        i+=2;
        j++;
    }
    cout << "key: " << encoded << endl;
    cout << "raw key: " << key << endl;
    
    cout << "raw iv: " << iv << endl;
    
    /* read in cipher*/
    std::fstream fcipher(argv[2],std::ios::in);
    fcipher >> cipherlen;
    fcipher >> hexcipher;
    fcipher.close();
    
    StringSource(hexcipher, true,
                 new HexDecoder(
                                new StringSink(cipher)
                                ) // HexEncoder
                 );
    
    cout << "cipher: " << hexcipher << endl;
    cout << "cipherlen: " << cipherlen << endl;
    cout << "raw cipher: " << cipher << endl;
    
    try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
        
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
    cout<< "the CBC-AES decrypt running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
    
}