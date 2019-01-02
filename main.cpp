//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: Main file to generate certificates.
//

#include <iostream>
#include <conio.h>
#include <vector>
#include <map>
#include <string>
#include "x509_generator.h"
#include "device_class.h"
#include "openssl/applink.c"
using namespace std;

int
main()
{
  bool res;
  CX509 certificate;
  CDevClass devClass;
  map<string, string> subjectData;

  // todo: input-> subjectData, Public Key
  subjectData = devClass.parseSubjectData("/C=US/L=MM/O=EDGE/OU=BE/CN=00:11:22:33:44:55:66/S=WI\0");
  certificate.GenerateCertificate(subjectData);
  res = certificate.writeToDisk();
  if (!res)
    cout << "\n Error in certificate generation";

  cout << "\n Successfully generated certificate..!!!\n";


  // verify map
  map<string, string> ::iterator itr;
  cout << "\nThe map gquiz1 is : \n";
  cout << "\tKEY\tELEMENT\n";
  for (itr = subjectData.begin(); itr != subjectData.end(); ++itr)
  {
    cout << '\t' << itr->first
      << '\t' << itr->second << '\n';
  }
  cout << endl;

  return 0;
}
