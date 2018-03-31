/*
@Author: Sonu Gupta

@Purpose: This file contains the common data, classes, macros used across the code.
*/


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
#define CSR_FILE  "csr.pem"
#define CER_FILE  "cert.crt"

// this is acting as CA
#define CA_FILE   "ca.pem"
#define CA_KEY    "cakey.pem"

#define VALIDITY  60 * 60 * 24 * 365

enum dataSize
{
  PUB_KEY_LEN = 65,
  COORDINATE_SIZE = 32,
  MAX_PATH = 260
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
    auto out = BIO_new_file(CER_FILE, "w");
    if (!PEM_write_bio_X509(out, x509))
    {
      //todo: error handling
    }
    BIO_free_all(out);
  }
};

class IX509_minimal
{
public:
  virtual void GenerateCertificate(boost::variant<X509_REQ*, X509*>) = 0;
  virtual void* ReadCertificate(std::string strCertificateName) = 0;
};

class SSLException
{
public:
 void what()
  {
   array<char, MAX_PATH> gszBuffer;
   ERR_error_string(ERR_peek_last_error(), gszBuffer.data());
   std::cout<<gszBuffer.data()<<endl;
  }
};
#endif