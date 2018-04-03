//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: Device Class containing customize functionality.
//

#include <iostream>
#include <map>
#include <string>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h> //needed
using namespace std;

// devclass:
/*
  1. get the basic data and make request_info
  2. request public key
  3. make partial csr using above two
  4. ask for digital signature digest
  5. create 'digital certificate'
  6. send 'digital certificate'

*/

class CDevClass
{
  char *m_request_str;

  BIO *m_reqbio = nullptr;
  BIO *m_outbio = nullptr;
  X509 *m_cert = nullptr;
  X509_REQ *m_certreq = nullptr;
  ASN1_INTEGER *aserial = nullptr;
  EVP_PKEY *ca_pvkey, *req_pubkey;
  EVP_MD const *digest = nullptr;
  X509 *m_newcert, *m_cacert;
  X509V3_CTX ctx;
  FILE *fp;
  long valid_secs = 31536000;

  // certificate related functions
  void addEntryToCertificate(X509_NAME* name, std::map<std::string, std::string>& subjectData);

public:

  CDevClass()=default;

  // following function will get "string /""/"" and will make new x509 certificate.
  void ParseAndInitializeCSR();

  // This function will add the 'public key'. here, we need to convert key from 'char*' to 'X509' format. And then add.
  void addPublicKeToCSRy();

  // This function will receive digital signature in "char*". So convert it to 'digest' or sha1 algorithmic form. 
  void getDigitalSignature();

  // Since, we have signature, do X509_Sign()
  void sendPartialCSRForSigning();



  std::string generatePartialCSR();
  std::string generateCompleteCSR();

  std::map<std::string, std::string> parseSubjectData(const char*);
};