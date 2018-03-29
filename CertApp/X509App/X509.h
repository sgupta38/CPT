#ifndef _X509_H_
#define _X509_H_

#include "interface.h"
#include "helper.h"

class CX509 : public IX509_minimal, public Chelper
{
  X509 *m_x509 = nullptr;
  X509_REQ *m_x509_req = nullptr;
  X509_NAME *m_x509_name = nullptr;

public:
  CX509();
  ~CX509();
  bool readCSR(std::string strFileName);
  bool VerifyCSR();
  void CreateCertificate();
  void SetVersion(int iVersion);
  void SetIssuerName(std::string strIssuerName);
  void SetOwnerName(std::string strOwnerName);
  void SetValidity(int iNotbefore, int iNotAfter);
  void SetExtension(); //todo
  bool SignTheCertificate(EVP_PKEY* privateKEy);
};

#endif _X509_H_