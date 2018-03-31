/*
@Author: Sonu Gupta

@Purpose: This file handles the routines of creation of CSR.
*/

#ifndef _X509_REQ_H_
#define _X509_REQ_H_

#include "interface.h"
#include "helper.h"

class CX509_req : public IX509_minimal, public Chelper
{
  X509_REQ* m_x509_req = nullptr;
  X509_NAME* m_x509_name = nullptr;
  EVP_PKEY* m_public_key = nullptr;
  SSLException error;

  std::vector<std::string> parseSubjectData(std::string);

  // interface routines
  void GenerateCertificate(boost::variant<X509_REQ*, X509*> cert) override;
  void* ReadCertificate(std::string strCertificateName) override;

public:
  CX509_req() :m_x509_req{ X509_REQ_new() }, m_x509_name{ X509_REQ_get_subject_name(m_x509_req) }, m_public_key{ EVP_PKEY_new() }{}
  ~CX509_req();

  // certificate function
  bool WriteCSR();
  X509_REQ* ReadCSR(std::string strFileName);
  bool setPublicKey(EC_KEY* ecKey);
  void SetSubjectData(std::string data);
  bool WriteDERCertificate(std::string strFilename);
  EC_KEY* getEC_Key(std::string strPublicKey, int CurveType, int asn1_flag);
  std::vector<unsigned char> CX509_req::DecodeSignature(std::string strSignature);
  void setSignature(std::vector<unsigned char> vtSignature, long version, int algorithm);

  void PrintLastError();
};
#endif _X509_H_