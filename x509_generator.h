//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: X.509 certificate generation using OpenSSL with C++11
//

#include <iostream>
#include <string>
#include <map>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define FILE_CERTIFICATE "cert.pem"
#define FILE_PRIVATEKEY "key.pem"

enum class Type{
  PRIVATE_KEY = 0,
  CERTIFICATE
};

class CX509
{
private:
  RSA *m_rsa;
  X509 *m_x509;
  EVP_PKEY *m_pKey;

  // certificate related functions
  void addEntryToCertificate(X509_NAME* name, std::map<std::string, std::string>& subjectData);

  //void addEntryToCertificate(X509_NAME* name, std::string field, std::string data);
  bool WriteToFile(Type type); // // Write pkey and certificates to file
  void PrintLAstError();

public:
   CX509();
  ~CX509();
  void GenerateCertificate(std::map<std::string, std::string>& subjectData);

  //void GenerateCertificate();
  bool writeToDisk();
};