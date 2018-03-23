//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: Wrapper functions for various functions of OpenSSL
//


#include "X509_generator.h"
#include <map>
using namespace std;

CX509::CX509() :m_pKey(EVP_PKEY_new()), m_rsa(RSA_generate_key(2048, RSA_F4, NULL, NULL)), m_x509(X509_new())
{
  EVP_PKEY_assign_RSA(m_pKey, m_rsa); // this is must
};

CX509::~CX509()
{
  if (nullptr != m_pKey)
  {
    EVP_PKEY_free(m_pKey);
  }

  if (nullptr != m_x509)
  {
    X509_free(m_x509);
  }
}

void CX509::GenerateCertificate(std::map<std::string, std::string>& subjectData)
{
  X509_NAME *name;
  ASN1_INTEGER_set(X509_get_serialNumber(m_x509), 1); // since some openSource HTTP fails if it is 0

  // Setting the fields in 'Certificate'
  X509_gmtime_adj(X509_get_notBefore(m_x509), 0);
  X509_gmtime_adj(X509_get_notAfter(m_x509), 60 * 60 * 24 * 365);

  X509_set_pubkey(m_x509, m_pKey); // sets the public key
  name = X509_get_subject_name(m_x509); //self-signed: thus, name of issuer = subject name

  addEntryToCertificate(name, subjectData);

  X509_set_issuer_name(m_x509, name);

  // signing
  X509_sign(m_x509, m_pKey, EVP_sha1());
}

void CX509::addEntryToCertificate(X509_NAME* name, std::map<std::string, std::string>& subjectData)
{
  for (auto itr = subjectData.begin(); itr != subjectData.end(); ++itr)
  {
    X509_NAME_add_entry_by_txt(
                              name,
                              (itr->first.c_str()),
                              MBSTRING_ASC,
                              (unsigned char*)(itr->second.c_str()),
                              -1,
                              -1,
                              0);
  }
}

bool CX509::WriteToFile(Type type)
{
  FILE *f = nullptr;
  int retValue = 0;
  // writing private key to file
  if (Type::PRIVATE_KEY == type)
  {
    f = fopen("key.pem", "wb");
    if (nullptr != f)
    {
      retValue = PEM_write_PrivateKey(f,
                                      m_pKey,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL,
                                      NULL
                                      );
      if (retValue != 1)
      {
        PrintLAstError();
        return false;
      }
    }
  }
  // writing certificate to file
  else if (Type::CERTIFICATE == type)
  {
    f = fopen("cert.csr", "wb");
    if (nullptr != f)
    {
      retValue = PEM_write_X509(f, m_x509);
      if (retValue != 1)
      {
        PrintLAstError();
        return false;
      }
    }
  }
  return true;
}

bool CX509::writeToDisk()
{
  bool ret = true;

  ret = WriteToFile(Type::PRIVATE_KEY);
  if (!ret)
    return false;

  ret = WriteToFile(Type::CERTIFICATE);
  if (!ret)
    return false;

  return true;
}

void CX509::PrintLAstError()
{
  // todo: handle it to show "string"
  char szBuffer[_MAX_PATH];
  memset(szBuffer, 0, _MAX_PATH);
  ERR_error_string(ERR_peek_last_error(), szBuffer);
  //printf("\n reason %s", ERR_reason_error_string(ERR_peek_last_error()));
  std::cout << szBuffer << std::endl;
}
