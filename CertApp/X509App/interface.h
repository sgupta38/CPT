#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <iostream>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <array>
#include <boost\variant.hpp>
using namespace std;

#define DER_FILE  "CertReqInfo.der"
#define CSR_FILE  "sonu.pem"

enum dataSize
{
  PUB_KEY_LEN = 65,
  COORDINATE_SIZE = 32,
};

// Functor
class CertficateGenerator :public boost::static_visitor<>{
public:
  void operator()(X509_REQ* x509_req) const
  {
    auto out = BIO_new_file(CSR_FILE, "w");
    if (!PEM_write_bio_X509_REQ(out, x509_req))
    {
      //todo: error handling
    }
    BIO_free_all(out);
  }

  void operator()(X509* x509) const
  {
    // todo
  }
};

class IX509_minimal
{
public:
  virtual void SetCountryName(std::string strCountryName) = 0;
  virtual void SetStateName(std::string strName) = 0;
  virtual void SetLocalityName(std::string strLocalityName) = 0;
  virtual void SetOrganizationName(std::string strOrganizationName) = 0;
  virtual void SetOrganizationalUnitName(std::string strOrganizationalUnitName) = 0;
  virtual void SetCommonName(std::string strCommonName) = 0;

  virtual void GenerateCertificate(boost::variant<X509_REQ*, X509*>) = 0;
  virtual void* ReadCertificate(int) = 0;
};

class SSLException
{
public:
 void what()
  {
   array<char, 260> gszBuffer;
   ERR_error_string(ERR_peek_last_error(), gszBuffer.data());
   std::cout<<gszBuffer.data()<<endl;
  }
};
#endif