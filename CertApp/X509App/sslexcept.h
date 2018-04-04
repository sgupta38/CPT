#ifndef _SSLEXCEPT_H
#define _SSLEXCEPT_H

#include <array>
using namespace std;

class SSLException
{
public:
  void what()
  {
    array<char, MAX_PATH> gszBuffer;
    ERR_error_string(ERR_peek_last_error(), gszBuffer.data());
    std::cout << gszBuffer.data() << endl;
  }
};

#endif