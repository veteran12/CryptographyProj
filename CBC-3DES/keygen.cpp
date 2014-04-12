//g++ keygen.cpp -o keygen -v -I/usr/include/cryptopp -L/Users/zhangtong/Desktop/Modern\ Cryptography/lab -lcryptopp
//./keygen
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
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include <fstream>

#include <time.h>

int main(int argc, char* argv[])
{
	std::clock_t start,finish;
	start=clock();
	
	AutoSeededRandomPool prng;
    
    /* generate key */
	unsigned char key[DES_EDE3::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
    
	string encoded;
    encoded.clear();
	StringSource(key, sizeof(key), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                )
                 );
	cout << "key: " << encoded << endl;
    cout << "raw key:" << key <<endl;
    
    std::fstream f("key.txt",std::ios::out);
    f<<encoded<<endl;
    f.close();
    
    finish=clock();
    cout<< "the CBC-DES keygen running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
}




