#pragma once
#include <string>

using namespace std;

namespace CryptoLog {
  class CryptoLog {
    public:
      virtual ~CryptoLog() {};
      virtual void open(const string &filename) = 0;
      virtual void close() = 0;
      virtual void write(const string &str) = 0;
      virtual string read() = 0;
      virtual string get_plain_text(void) = 0;
  };
}

