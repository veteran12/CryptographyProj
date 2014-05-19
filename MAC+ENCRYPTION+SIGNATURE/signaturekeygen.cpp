#ifndef MYRSA_H_
#define MYRSA_H_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include <string>

#include <rsa.h>
#include <hex.h>
#include <osrng.h>
#include <files.h>
#include <md5.h>
#include <time.h>
using namespace std;
using namespace CryptoPP;

class MyRSA
{
public:

    
	void GenerateRSAKey(unsigned int keyLength, const char *privFilename,
                        const char *pubFilename);
    
private:
	AutoSeededRandomPool _rng;
};

#endif /* MYRSA_H_ */



/*
 * generate the RSA public key and private key in separate file
 */
void MyRSA::GenerateRSAKey(unsigned int keyLength, const char *privFilename,
                           const char *pubFilename)
{   AutoSeededRandomPool rng;
    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 1024);
    if (!priv.Validate(rng, 3))
    {
        throw("RSA key generation failed");
    }
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.MessageEnd();
    
    
    RSA::PublicKey pub;
    pub.AssignFrom(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}


int main() {
    char privFilename[128] = "signsecretkey.txt", pubFilename[128] = "signpublickey.txt";
    unsigned int keyLength = 1024;
    clock_t start, finish;
    double duration;
 
    MyRSA rsa;
    
    
    start = clock();
    cout << "============signature generate key================" << endl;
    rsa.GenerateRSAKey(keyLength, privFilename, pubFilename);
    
    finish = clock();
    duration = (double) (finish - start) / CLOCKS_PER_SEC;
    cout << "The cost is : " << duration << " seconds" << endl;
    
    
    
}