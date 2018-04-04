#ifndef _COMMON_H
#define _COMMON_H

#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <map>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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



#endif
