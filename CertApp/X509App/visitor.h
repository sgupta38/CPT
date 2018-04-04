#ifndef _VISITOR_H
#define _VISITOR_H


#include <boost\variant.hpp>
using namespace std;

// Functors
class CertficateGenerator :public boost::static_visitor<>{
public:
  std::string strFilename;
  void operator()(X509_REQ* x509_req) const
  {
    auto out = BIO_new_file(strFilename.c_str(), "w");
    if (!PEM_write_bio_X509_REQ(out, x509_req))
    {
      //todo: error handling
    }
    BIO_free_all(out);
  }

  void operator()(X509* x509) const
  {
    auto out = BIO_new_file(strFilename.c_str(), "w");
    if (!PEM_write_bio_X509(out, x509))
    {
      //todo: error handling
    }
    BIO_free_all(out);
  }
};

#endif