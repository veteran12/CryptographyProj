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
#include <map>


std::map<char,int> mapp;
class MyRSA
{
public:

    
	string MD5(const char * message);
	string MD5File(const char * filename);
	bool VerifyString(const char * pubFilename, const char * messsage,
                      const SecByteBlock &SecByteBlock);
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
 * verify the file with the public key, and return yes or no
 */
bool MyRSA::VerifyString(const char * pubFilename, const char * message,
                         const SecByteBlock & signature)
{
	// calculate the md5 of the message
	string digest = MD5(message);
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Verifier verifier(pubFile);
    
	bool result = verifier.VerifyMessage((const byte*) digest.c_str(),
                                         digest.length(), signature, signature.size());
	return result;
}


int main(int argc, char* argv[]) {
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
    clock_t start, finish;
    double duration;
    
    
    
    MyRSA rsa;
    
    
    cout << "============Verify start=================" << endl;
    start = clock();
    string message;
    std::fstream fme(argv[2],std::ios::in);
    fme >>message;
    fme.close();
    std::cout<<"Hex Message is " << message <<std::endl;
   /*
    string messagedecoded;
    StringSource(message,true,
                 new HexDecoder(
                                new StringSink(messagedecoded)
                                )
                 );
    std::cout<< " Message is " <<messagedecoded<<std::endl;
    */
    
    //transfer signature from hex format to string format
    SecByteBlock signature;
    string sign;
    std::fstream fsig(argv[3],std::ios::in);
    fsig >> sign;
    fsig.close();
    //cout << "The Signature is : " <<  sign << endl;
    
    signature.resize(sign.size()/2);
    for(int i=0,j=0;i<sign.size();){
        signature[j]=mapp[sign[i]]*16+mapp[sign[i+1]];
        i+=2;
        j++;
        
    }
    
    //cout << "The Signature size is : " << signature.size() << endl;
    
    
    
    if (rsa.VerifyString(argv[1], message.c_str(), signature)) {
        cout << "verify : yes" << endl;
        std::fstream fyn("yesno_output.txt",std::ios::out);
        fyn<<"yes"<<std::endl;
        fyn.close();
    } else {
        cout << "verify : no" << endl;
        std::fstream fyn("yesno_output.txt",std::ios::out);
        fyn<<"no"<<std::endl;
        fyn.close();
    }
    
    finish = clock();
    duration = (double) (finish - start) / CLOCKS_PER_SEC;
    cout << "The verify cost is : " << duration << " seconds" << endl;
    return 0;
}