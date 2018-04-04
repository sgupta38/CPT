/*
@Author: Sonu Gupta

@Purpose: This file contains the common data, classes, macros used across the code.
*/


#ifndef _INTERFACE_H
#define _INTERFACE_H

#include "common.h"
#include "visitor.h"

class IX509_minimal
{
public:
  virtual void GenerateCertificate(boost::variant<X509_REQ*, X509*>, std::string strFileName) = 0;
  virtual void* ReadCertificate(std::string strCertificateName) = 0;
};

#endif