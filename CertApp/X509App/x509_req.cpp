/*
@Author: Sonu Gupta

@Purpose: This file handles the routines of creation of CSR.
*/


#include "X509_req.h"
#include<boost/algorithm/string/split.hpp>
#include<boost/algorithm/string/constants.hpp>
#include<boost/algorithm/string/classification.hpp>

using namespace boost::algorithm;

CX509_req::CX509_req() :m_x509_req{ X509_REQ_new() }, m_x509_name{ X509_REQ_get_subject_name(m_x509_req) }, m_public_key{ EVP_PKEY_new() }
{
}

CX509_req::~CX509_req()
{
  if (m_x509_req)
    X509_REQ_free(m_x509_req);
}

void CX509_req::SetSubjectData(std::string data)
{
  auto subjectData = parseSubjectData(data);
  for (auto i = 1; i < subjectData.size(); i += 2)
    X509_NAME_add_entry_by_txt(m_x509_name, subjectData[i].data(), MBSTRING_ASC, (unsigned char*)subjectData[i+1].data(), -1, -1, 0);
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
    auto x = BN_bin2bn((unsigned char*)&publicKey[1], COORDINATE_SIZE, NULL);
    auto y = BN_bin2bn((unsigned char*)&publicKey[1 + COORDINATE_SIZE], COORDINATE_SIZE, NULL);

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

bool CX509_req::setPublicKey(EC_KEY* ecKey)
{
  EVP_PKEY_assign_EC_KEY(m_public_key, ecKey);
  if (!X509_REQ_set_pubkey(m_x509_req, m_public_key))
  {
    return false;
  }

  if (ecKey)
    EC_KEY_free(ecKey);

  return true;
}

// writing to .der file
bool CX509_req::WriteDERCertificate(std::string strFilename)
{
  unsigned char *derReqInfo = NULL;
  auto size = i2d_X509_REQ_INFO(m_x509_req->req_info, &derReqInfo);
  if (size <= 0)
  {
    //todo: error handling
    return false;
  }

  std::ofstream createDERFile(strFilename.c_str(), std::ofstream::out | std::ofstream::binary);
  createDERFile.write(reinterpret_cast<const char*>(derReqInfo), size);
  createDERFile.close();

  return true;
}

bool CX509_req::WriteCSR(std::string strFileName)
{
  GenerateCertificate(m_x509_req, strFileName);
  return true;
}

X509_REQ* CX509_req::ReadCSR(std::string strFileName)
{
  return reinterpret_cast<X509_REQ*>(ReadCertificate(strFileName.c_str()));
}

//delme:
void CX509_req::PrintLastError()
{
  char gszBuffer[260];
  memset(gszBuffer, 0, _MAX_PATH);
  ERR_error_string(ERR_peek_last_error(), gszBuffer);
  
  // todo:
  std::cout<<"reason: %s\n"<< ERR_lib_error_string(9);
  std::cout<<"reason: %s\n"<<ERR_func_error_string(103);
  std::cout<<"reason: %s\n"<<ERR_reason_error_string(13);
  std::cout<<"%s\n"<<gszBuffer;
}

std::vector<unsigned char> CX509_req::DecodeSignature(std::string strSignature)
{
  std::vector<unsigned char> vtSignature(strlen(strSignature.c_str()));
  base64Decode(strSignature, vtSignature);
  return vtSignature;
}

void CX509_req::setSignature(std::vector<unsigned char> vtSignature, long version, int algorithm)
{
  X509_REQ_set_version(m_x509_req, version);
  ASN1_BIT_STRING_set(m_x509_req->signature, vtSignature.data(), vtSignature.size());
  m_x509_req->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
  m_x509_req->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  m_x509_req->sig_alg->algorithm = OBJ_nid2obj(algorithm);
  m_x509_req->sig_alg->parameter = ASN1_TYPE_new();
  m_x509_req->sig_alg->parameter->type = V_ASN1_NULL;
}

void CX509_req::GenerateCertificate(boost::variant<X509_REQ*, X509*> certificate, std::string strFileName)
{
  CertficateGenerator f;
  f.strFilename = std::move(strFileName);
  boost::apply_visitor(f, certificate);
}

void* CX509_req::ReadCertificate(std::string strCertificateName)
{
  FILE *fp;
  X509_REQ* x509_req;

  /* read in the request */
  if (!(fp = fopen(strCertificateName.c_str(), "r")))
    std::cout << "Error reading request file";
  if (!(x509_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL)))
    std::cout << "Error reading request in file";
  fclose(fp);

  return x509_req;
}

std::vector<std::string> CX509_req:: parseSubjectData(std::string data)
{
  // add _SCL_SECURE_NO_WARNINGS flag in preprocessor.
  std::vector<std::string> subjectData;
  split(subjectData, data, is_any_of("/="), token_compress_off);
  return subjectData;
}

