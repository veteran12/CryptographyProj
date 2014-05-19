#ifndef MYRSA_H_
#define MYRSA_H_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include <string>

#include <rsa.h>
#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
#include <osrng.h>
#include <files.h>
#include <md5.h>
#include <time.h>
using namespace std;
using namespace CryptoPP;

class MyRSA
{
public:

    
	string MD5(const char * message);

    
	SecByteBlock SignString(const char *privFilename, const char * message);

private:
	AutoSeededRandomPool _rng;
};

#endif /* MYRSA_H_ */


/*
 * calcuate the string 'message' 's hash value
 */
string MyRSA::MD5(const char * message)
{
	string digest;
	Weak::MD5 md5;
	StringSource(message, true,
                 new HashFilter(md5, new HexEncoder(new StringSink(digest))));
	return digest;
}



/*
 * sign the string with the private key, and generate the signature
 */
SecByteBlock MyRSA::SignString(const char * privFilename, const char * message)
{
	// calculate the md5(HASH) of the message
	string digest = MD5(message);
	FileSource priFile(privFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Signer priv(priFile);
    
	// Create signature space
	size_t length = priv.MaxSignatureLength();
	SecByteBlock signature(length);
    
	// sign message
	priv.SignMessage(_rng, (const byte*) digest.c_str(), digest.length(),
                     signature);
    
	return signature;
}


int main(int argc, char* argv[]) {
    clock_t start, finish;
    double duration;
    
    
    MyRSA rsa;
    
    
    
    cout << "============Sign start=================" << endl;
    start = clock();
    string hybridpublickey,hpubklen;
    std::fstream fhpub("publickey.txt",std::ios::in);
    fhpub >> hpubklen;
    fhpub >> hybridpublickey;
    fhpub.close();
    
    string bobid="this is bob's id";
    string bobidhex;
    StringSource(bobid,true,
                 new HexEncoder(
                                new StringSink(bobidhex)
                                )
                 );

    cout<< "Id is : " << bobid << endl;
    
    std::fstream fmess("message.txt",std::ios::out);
    fmess<<hybridpublickey<<bobidhex<<std::endl;
    fmess.close();
    cout << "============hybrid public key and id included in messeage.txt=================" << endl;
    string message;
    std::fstream fme(argv[3],std::ios::in);
    fme >>message;
    fme.close();
    std::cout<<" Hex Message is " <<"\n"<<message <<std::endl;
    
    string signaturehex;
    SecByteBlock signature = rsa.SignString(argv[2], message.c_str());
    StringSource(signature, signature.size(), true,
                 new HexEncoder(
                                new StringSink(signaturehex)
                                )
                 );
    //cout << "The Signature size is : " << signature.size() << endl;
    cout << "The Signature is : " << signaturehex << endl;
    
    
    std::fstream fs("signature.txt",std::ios::out);
    fs<<signaturehex<<std::endl;
    fs.close();
    
    
    finish = clock();
    duration = (double) (finish - start) / CLOCKS_PER_SEC;
    cout << "The sign cost is : " << duration << " seconds" << endl;
    return 0;
}