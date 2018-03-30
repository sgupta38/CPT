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

  // todo: tuple?
  std::string m_commonName;
  std::string m_countryName;
  std::string m_StateName;
  std::string m_LocalityName;
  std::string m_OrganizationName;
  std::string m_OrganizationalUnitName;

public:
  CX509_req() :m_x509_req{ X509_REQ_new() }, m_x509_name{ X509_REQ_get_subject_name(m_x509_req) }, m_public_key{ EVP_PKEY_new() }{}
  ~CX509_req();

  void SetSubjectData();

  // interface routines
  void SetCountryName(std::string strCountryName) override;
  void SetStateName(std::string strName) override;
  void SetLocalityName(std::string strLocalityName) override;
  void SetOrganizationName(std::string strOrganizationName) override;
  void SetOrganizationalUnitName(std::string strOrganizationalUnitName) override;
  void SetCommonName(std::string strCommonName) override;
  void GenerateCertificate(boost::variant<X509_REQ*, X509*> cert) override;
  void* ReadCertificate(int) override;


  // certificate function
  bool setPublicKey(EC_KEY* ecKey);
  X509_REQ* ReadCertificate(std::string strCSRName);
  bool WriteDERCertificate(std::string strFilename);
  bool WriteCSR();
  X509_REQ* ReadCSR();

  void setSignature(std::vector<unsigned char> vtSignature, long version, int algorithm);
  std::vector<unsigned char> CX509_req::DecodeSignature(std::string strSignature);

  // Customized functions
  EC_KEY* getEC_Key(std::string strPublicKey, int CurveType, int asn1_flag);

  void PrintLastError();
};
#endif _X509_H_