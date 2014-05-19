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

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include <fstream>

#include <time.h>

int main(int argc, char* argv[])
{
	std::clock_t start,finish;
	start=clock();
	AutoSeededRandomPool prng;
    
	/* generate key for mac */
	unsigned char key1[16];
	prng.GenerateBlock(key1, sizeof(key1));
	
	/* generate key for encrypt */
	unsigned char key2[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key2, sizeof(key2));
    
	string encoded1,encoded2;
	encoded1.clear();
	encoded2.clear();
	
	StringSource(key1, sizeof(key1), true,
                 new HexEncoder(
                                new StringSink(encoded1)
                                )
                 );
	cout << "key for mac is:" << key1 <<endl;
	cout << "hexadecimal key for mac is: " << encoded1 << endl;
	
	StringSource(key2, sizeof(key2), true,
                 new HexEncoder(
                                new StringSink(encoded2)
                                )
                 );
	cout << "key for encrypt is:" << key2 <<endl;
	cout << "hexadecimal key for encrypto is: " << encoded2 << endl;
   
    
    std::fstream f("key.txt",std::ios::out);
    f<<encoded1<<endl;
    f<<encoded2<<endl;
    f.close();
    
    finish=clock();
    cout<< "the keygen running time is " << difftime(finish,start) << " ms" << endl;
    
    return 0;
}




