/*
@Author: Sonu Gupta

@Purpose: This file handles the routines for processing CSR and creating final certificate.
*/

#ifndef _X509_H_
#define _X509_H_

#include "interface.h"
#include "helper.h"

class CX509 : public IX509_minimal, public Chelper
{
public:
  CX509();
  ~CX509();

  void readCSR(std::string strFileName);
  bool VerifyCSR();
  void CreateCertificate(std::string strFileName);
  void SetVersion(int iVersion);
  void SetSubjectData();
  void SetIssuerName();
  void SetValidity(int iNotbefore, int iNotAfter);
  void SetPublicKey();
  void SetExtension(); //todo
  bool SignTheCertificate();

private:
  // interface routines
  void GenerateCertificate(boost::variant<X509_REQ*, X509*> cert, std::string strFileName) override;
  void* ReadCertificate(std::string strFileName) override;
  X509* ReadRootCA(std::string strFileName);
  EVP_PKEY* ReadRootPrivateKey();

  X509 *m_x509, *m_root_x509;
  X509_REQ *m_x509_req;
  X509_NAME *m_x509_name;
  EVP_PKEY *m_root_private_key;

};

#endif _X509_H_