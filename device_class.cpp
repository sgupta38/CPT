//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: Class containing customize functionality.
//

#include "device_class.h"
#include <string>
#include <vector>
#include <map>
using namespace std;

std::map<std::string, std::string> CDevClass::parseSubjectData(const char* pSubjectData)
{
  std::string subject(pSubjectData);
  std::vector<string> data;
  map<string, string> subjectData;

  char *pTemp = (char*)subject.c_str();
  string key = "";
  string value = "";

  while (*pTemp == '/')
  {
    pTemp++;

    if (*pTemp == '\0')
      break;

    while (*pTemp != '/')
    {
      key += *pTemp;
      pTemp++;
      if (*pTemp == '=')
      {
        pTemp++;
        while (*pTemp != '/')
        {
          if (*pTemp == '\0')
            break;

          value += *pTemp;
          pTemp++;
        }
        subjectData.insert(make_pair<string, string>(key.c_str(), value.c_str()));
        key.clear();
        value.clear();
        break;
      }
    }
  }

  return subjectData;
}

void CDevClass::ParseAndInitializeCSR()
{
  m_newcert = X509_new();
  X509_NAME *name;
  ASN1_INTEGER_set(X509_get_serialNumber(m_newcert), 1); // since some openSource HTTP fails if it is 0

  // Setting the fields in 'Certificate'
  X509_gmtime_adj(X509_get_notBefore(m_newcert), 0);
  X509_gmtime_adj(X509_get_notAfter(m_newcert), 60 * 60 * 24 * 365);

  map<string, string> subjectData;

  // todo: input-> subjectData, Public Key
  subjectData = parseSubjectData("/C=US/L=MM/O=EDGE/OU=BE/CN=00:11:22:33:44:55:66/S=WI\0");
  name = X509_get_subject_name(m_newcert); //self-signed: thus, name of issuer = subject name

  addEntryToCertificate(name, subjectData);

  X509_set_issuer_name(m_newcert, name);

}

void CDevClass::addEntryToCertificate(X509_NAME* name, std::map<std::string, std::string>& subjectData)
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
//
//void CDevClass::getPublicKeyFrom()
//{
//
//
//}
