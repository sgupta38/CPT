#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <iostream>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>

class IX509_minimal
{
public:
  virtual void SetCountryName(std::string strCountryName) = 0;
  virtual void SetStateName(std::string strName) = 0;
  virtual void SetLocalityName(std::string strLocalityName) = 0;
  virtual void SetOrganizationName(std::string strOrganizationName) = 0;
  virtual void SetOrganizationalUnitName(std::string strOrganizationalUnitName) = 0;
  virtual void SetCommonName(std::string strCommonName) = 0;
};

#endif