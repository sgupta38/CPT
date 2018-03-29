#include "X509_req.h"

CX509_req::~CX509_req()
{
  if (m_public_key)
    EVP_PKEY_free(m_public_key);

  if (m_x509_name)
    X509_NAME_free(m_x509_name);

  // todo: exception here

  //if (m_x509_req)
  //  X509_REQ_free(m_x509_req);
}

void CX509_req::SetCountryName(std::string strCountryName)
{
  m_countryName = strCountryName;
}

void CX509_req::SetStateName(std::string strStateName)
{
  m_StateName = strStateName;
}

void CX509_req::SetLocalityName(std::string strLocalityName)
{
  m_LocalityName = strLocalityName;
}

void CX509_req::SetOrganizationName(std::string strOrganizationName)
{
  m_OrganizationName = strOrganizationName;
}

void CX509_req::SetOrganizationalUnitName(std::string strOrganizationalUnitName)
{
  m_OrganizationalUnitName = strOrganizationalUnitName;
}

void CX509_req::SetCommonName(std::string strCommonName)
{
  m_commonName = strCommonName;
}

void CX509_req::SetSubjectData()
{
  X509_NAME_add_entry_by_txt(m_x509_name, "C", MBSTRING_ASC, (unsigned char*)m_countryName.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(m_x509_name, "ST", MBSTRING_ASC, (unsigned char*)m_StateName.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(m_x509_name, "L",  MBSTRING_ASC, (unsigned char*)m_LocalityName.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(m_x509_name, "OU", MBSTRING_ASC, (unsigned char*)m_OrganizationalUnitName.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(m_x509_name, "CN", MBSTRING_ASC, (unsigned char*)m_commonName.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(m_x509_name, "O", MBSTRING_ASC, (unsigned char*)m_OrganizationName.c_str(), -1, -1, 0);
}

EC_KEY* CX509_req::getEC_Key(std::string strPublicKey, int CurveType, int asn1_flag)
{
  int retVal;
  EC_KEY *ecKey = nullptr;
  std::vector<unsigned char> publicKey(PUB_KEY_LEN);

  base64Decode(strPublicKey, publicKey);

  ecKey = EC_KEY_new_by_curve_name(CurveType);
  if (NULL == ecKey)
  {
    return 0;
  }

  EC_KEY_set_asn1_flag(ecKey, asn1_flag);

  if (0x04 == publicKey[0])
  {
    BIGNUM* x = BN_bin2bn((unsigned char*)&publicKey[1], COORDINATE_SIZE, NULL);
    BIGNUM* y = BN_bin2bn((unsigned char*)&publicKey[1 + COORDINATE_SIZE], COORDINATE_SIZE, NULL);

    if ((retVal = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y)) != 1)
    {
      //todo
      std::cout << "EC_KEY_set_public_key_affine_coordinates() failed";
    }

    BN_free(x);
    BN_free(y);
  }

  return ecKey;
}

void CX509_req::setPublicKey(EC_KEY* ecKey)
{
  EVP_PKEY_assign_EC_KEY(m_public_key, ecKey);
  if (ecKey)
    EC_KEY_free(ecKey);
}

X509_REQ* CX509_req:: ReadCertificate()
{
  // todo
  return m_x509_req;
}

// writing to .der file
bool CX509_req::WriteDERCertificate(std::string strFilename)
{
  unsigned char *derReqInfo = NULL;
  int size = i2d_X509_REQ_INFO(m_x509_req->req_info, &derReqInfo);
  if (size <= 0)
  {
    //todo: error handling
  }

  std::ofstream createDERFile(strFilename.c_str(), std::ofstream::out | std::ofstream::binary);
  createDERFile.write(reinterpret_cast<const char*>(derReqInfo), size);
  createDERFile.close();

  return true;
}

void CX509_req::WriteCSR(std::string strFileName)
{
  BIO* out = BIO_new_file(strFileName.c_str(), "w");
  if (!PEM_write_bio_X509_REQ(out, m_x509_req))
  {
    //todo: error handling
  }
}
