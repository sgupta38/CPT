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
  X509 *m_x509 = nullptr, *m_root_x509 = nullptr;
  X509_REQ *m_x509_req = nullptr;
  X509_NAME *m_x509_name = nullptr;
  EVP_PKEY *m_root_private_key = nullptr;

  // interface routines
  void GenerateCertificate(boost::variant<X509_REQ*, X509*> cert, std::string strFileName) override;
  void* ReadCertificate(std::string strFileName) override;
  X509* ReadRootCA(std::string strFileName);
  EVP_PKEY* ReadRootPrivateKey();

public:
  CX509() :m_x509{ X509_new() }, m_root_x509{ ReadRootCA(CA_FILE) }, m_root_private_key{ ReadRootPrivateKey()}{}
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
};

#endif _X509_H_