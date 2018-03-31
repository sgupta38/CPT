/*
@Author: Sonu Gupta

@Purpose: This file has helper routines used across code.
*/

#include "helper.h"
#include <iostream>

int  Chelper::base64Decode(std::string strBase64data, std::vector<unsigned char>& outData)
{
  auto len = strlen(strBase64data.c_str());
  outData.resize(len);

  // Convert base64 version of ECC public into binary.
  auto b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  auto bmem = BIO_new_mem_buf(strBase64data.c_str(), len);
  bmem = BIO_push(b64, bmem);

  auto retVal = BIO_read(bmem, outData.data(), outData.size());
  if (0 == retVal)
  {
    BIO_free_all(bmem);

    return 0;
  }
  BIO_free_all(bmem);

  outData.resize(retVal);
}

void Chelper::hashData(unsigned char* strdata, std::map<unsigned char*, int> outData)
{
  SHA256_CTX sha256;
  auto itr = outData.begin();

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, itr->first, itr->second);
  if (0 == SHA256_Final(strdata, &sha256))
    std::cout << "Error Occured";  //todo: add exception class for error handling
}