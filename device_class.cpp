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