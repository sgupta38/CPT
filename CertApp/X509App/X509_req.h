#ifndef _X509_REQ_H_
#define _X509_REQ_H_

#include "interface.h"
#include "helper.h"

enum dataSize
{
  PUB_KEY_LEN = 65,
  COORDINATE_SIZE = 32
};

class CX509_req: public IX509_minimal, public Chelper
{
  X509_REQ* m_x509_req = nullptr;
  X509_NAME* m_x509_name = nullptr;
  EVP_PKEY* m_public_key = nullptr;

  // todo: tuple?
  std::string m_commonName;
  std::string m_countryName;
  std::string m_StateName;
  std::string m_LocalityName;
  std::string m_OrganizationName;
  std::string m_OrganizationalUnitName;

public:
  CX509_req() :m_x509_req{ X509_REQ_new() }, m_x509_name{ X509_REQ_get_subject_name(m_x509_req) }{}
  ~CX509_req();

  void SetSubjectData();

  // Setters
  void SetCountryName(std::string strCountryName);
  void SetStateName(std::string strName);
  void SetLocalityName(std::string strLocalityName);
  void SetOrganizationName(std::string strOrganizationName);
  void SetOrganizationalUnitName(std::string strOrganizationalUnitName);
  void SetCommonName(std::string strCommonName);

  // certificate function
  void setPublicKey(EC_KEY* ecKey);
  X509_REQ* ReadCertificate();
  bool WriteDERCertificate(std::string strFilename);
  void WriteCSR(std::string strFileName);

  // Customized functions
  EC_KEY* getEC_Key(std::string strPublicKey, int CurveType, int asn1_flag);
};
#endif _X509_H_