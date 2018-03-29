#include "helper.h"
#include <iostream>

int  Chelper::base64Decode(std::string strBase64data, std::vector<unsigned char>& outData)
{
  BIO *b64, *bmem;
  int retVal;

  // Convert base64 version of ECC public into binary.
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(strBase64data.c_str(), strBase64data.length());
  bmem = BIO_push(b64, bmem);
  retVal = BIO_read(bmem, outData.data(), outData.size());
  if (0 == retVal)
  {
    BIO_free_all(bmem);
    return 0;
  }
  BIO_free_all(bmem);
}

void Chelper::hashData(unsigned char* strdata, std::map<unsigned char*, int> outData)
{
  SHA256_CTX sha256;
  std::map<unsigned char*, int>::iterator itr = outData.begin();

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, itr->first, itr->second);
  if (0 == SHA256_Final(strdata, &sha256))
    std::cout << "Error Occured";  //todo: add exception class for error handling
}