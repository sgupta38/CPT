/*
 @Author Sonu Gupta.
 @Purpose. Minimal example depicts how certificate sign request is made.

*/


#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main()
{
  X509_REQ *x509_req = NULL;
  X509_NAME *x509_name = NULL;
  BIO *out = NULL;
  BIO *err = NULL;
  const char      *szPath = "x509Req.pem";

  // key generation =================================================================

  EVP_PKEY* pKey = EVP_PKEY_new();
  if (NULL == pKey)
  {
    printf("EVP_PKEY_new failed..!! \n");
    return -1;
  }

  RSA* rsa = RSA_generate_key(
    2048,
    RSA_F4,
    NULL,
    NULL
    );
  if (NULL == rsa)
  {
    printf("RSA_generate_key failed..!! \n");
    return -1;
  }

  EVP_PKEY_assign_RSA(pKey, rsa);

  // Certificate request ============================================================

  x509_req = X509_REQ_new();
  X509_REQ_set_version(x509_req, 1);

  x509_name = X509_REQ_get_subject_name(x509_req);

  // Setting subject data ==================================
  // Country Name
  X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC,
    (unsigned char*)"IN", -1, -1, 0);

  // State
  X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC,
    (unsigned char*)"Maharashtra", -1, -1, 0);

  // Location
  X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC,
    (unsigned char*)"Pune", -1, -1, 0);

  // Organization Name
  X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC,
    (unsigned char*)"Edge Corp.", -1, -1, 0);

  // Organization Department
  X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC,
    (unsigned char*)"Development", -1, -1, 0);

  // Common Name
  X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
    (unsigned char*)"localhost", -1, -1, 0);


  // Set Public Key ==============================================
  X509_REQ_set_pubkey(x509_req, pKey);


  // Sign the certificate =========================================
  X509_REQ_sign(x509_req, pKey, EVP_sha1());



  // write certificate =============================================
  out = BIO_new_file(szPath, "w");
  PEM_write_bio_X509_REQ(out, x509_req);



  // free memory ====================================================
  X509_REQ_free(x509_req);
  BIO_free_all(out);



  return 0;
}