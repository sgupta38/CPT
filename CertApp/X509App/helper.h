/*
@Author: Sonu Gupta

@Purpose: This file has helper routines used across code.
*/

#ifndef _HELPER_
#define _HELPER_

#include <vector>
#include <map>

class Chelper
{
public:
  int base64Decode(std::string strBase64data, std::vector<unsigned char>& outData);
  void hashData(unsigned char* strdata, std::map<unsigned char*, int> outData);

};

#endif