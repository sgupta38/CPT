/*
@Author: Sonu Gupta

@Purpose: This file handles the routines for processing CSR and creating final certificate.
*/


#include "X509.h"

CX509::CX509() :m_x509{ X509_new() }, m_root_x509{ ReadRootCA(CA_FILE) }, m_root_private_key{ ReadRootPrivateKey() }
{
}


CX509::~CX509()
{
  if (m_x509)
    X509_free(m_x509);

}
void CX509::readCSR(std::string strFileName)
{
  FILE *fp;

  /* read in the request */
  if (!(fp = fopen(CSR_FILE, "r")))
  {
    std::cout << "Error reading request file"<<endl;
    return;
  }

  if (!(m_x509_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL)))
  {
    std::cout << "Error reading request in file"<<endl;
    return;
  }

  fclose(fp);
}

bool CX509::VerifyCSR()
{
  EVP_PKEY *pKey;
  /* verify signature on the request */

  if (!(pKey = X509_REQ_get_pubkey(m_x509_req)))
  {
    std::cout << "Error getting public key from request" << endl;
    return false;
  }

  // how to?
  if (X509_REQ_verify(m_x509_req, pKey) != 1)
  std::cout << "Error verifying signature on certificate";

    return true;
}

void CX509::SetPublicKey()
{
    EVP_PKEY *pKey;

    if (!(pKey = X509_REQ_get_pubkey(m_x509_req)))
    {
      std::cout << "Error getting public key from request" << endl;
      return;
    }

    if (X509_set_pubkey(m_x509, pKey) != 1)
    {
      cout << "Error in setting subject name" << endl;
      return;
    }
}


void CX509::SetSubjectData()
{
  if (!(m_x509_name = X509_REQ_get_subject_name(m_x509_req)))
  {
    cout << "Error in reading subject name"<<endl;
    return;
  }

  if (X509_set_subject_name(m_x509, m_x509_name) != 1)
  {
    cout << "Error in setting subject name"<<endl;
    return;
  }
}


void CX509::CreateCertificate(std::string strFileName)
{
  GenerateCertificate(m_x509, strFileName);
}

void CX509::SetVersion(int iVersion)
{
  if (X509_set_version(m_x509, 1) != 1)
  {
    cout << "Error in setting version"<<endl;
    return;
  }
}

void CX509::SetIssuerName()
{
  X509_NAME* name = nullptr;

  // Note: Since issuer name is read from another CA certificate.
  if (!(name = X509_get_subject_name(m_root_x509)))
  {
    cout << "Error in setting issuer name" << endl;
    return;
  }

  if (X509_set_issuer_name(m_x509, name) != 1)
  {
    cout << "Error in setting issuer name"<<endl;
    return;
  }
}

void CX509::SetValidity(int iNotbefore, int iNotAfter)
{
  /* set duration for the certificate */
  if (!(X509_gmtime_adj(X509_get_notBefore(m_x509), iNotbefore)))
  {
    cout << "Error setting beginning time of the certificate" << endl;
    return;
  }
  if (!(X509_gmtime_adj(X509_get_notAfter(m_x509), iNotAfter)))
  {
    cout << "Error setting ending time of the certificate" << endl;
    return;
  }
}

void CX509::SetExtension()
{
  // todo
}

bool CX509::SignTheCertificate( )
{
  const EVP_MD *digest = nullptr;

  if (EVP_PKEY_type(m_root_private_key->type) == EVP_PKEY_DSA)
    digest = EVP_dss1();
  else if (EVP_PKEY_type(m_root_private_key->type) == EVP_PKEY_RSA)
    digest = EVP_sha1();
  else
    cout << "Error checking CA private key for a valid digest" << endl;

  if (!(X509_sign(m_x509, m_root_private_key, digest)))
    cout << "Error signing certificate" << endl;

  return true;
}

void CX509::GenerateCertificate(boost::variant<X509_REQ*, X509*> cert, std::string strFileName)
{
  CertficateGenerator f;
  f.strFilename = strFileName;
  boost::apply_visitor(f, cert);
}

void* CX509::ReadCertificate(std::string strFileName)
{
  FILE *fp;
  X509* x509;

  /* read in the request */
  if (!(fp = fopen(strFileName.c_str(), "r")))
    std::cout << "Error reading request file";
  if (!(x509 = PEM_read_X509(fp, NULL, NULL, NULL)))
    std::cout << "Error reading request in file";
  fclose(fp);

  return x509;
}

X509* CX509::ReadRootCA(std::string strFileName)
{
    return reinterpret_cast<X509*>(ReadCertificate(strFileName.c_str()));
}

EVP_PKEY* CX509:: ReadRootPrivateKey()
{
  FILE *fp;
  EVP_PKEY* CApkey;

  /* read in the CA private key */
  if (!(fp = fopen(CA_KEY, "r")))
    std::cout << "Error reading request file";

  if (!(CApkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) //Password
    std::cout << "Error reading request in file";
  fclose(fp);

  return CApkey;
}
