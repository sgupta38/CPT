//
//  @Author: Sonu Gupta
//  @Date: 23/3/18
//  @Purpose: Device Class containing customize functionality.
//

#include <iostream>
#include <map>

class CDevClass
{
  std::string m_devInfo;
  std::string m_CSR = "";
public:

  CDevClass()=default;
  //CDevClass(std::string devInfo) :m_devInfo(devInfo){} // look by uncommenting

  void getDeviceInfo(std::string);
  
  std::string generatePartialCSR();
  std::string generateCompleteCSR();

  std::map<std::string, std::string> parseSubjectData(const char*);
};