#include <iostream>
#include "CryptoLog/Blowfish_CBC.h"
#include "CryptoLog/Blowfish_CFB.h"
#include "CryptoLog/Blowfish_CTR.h"
#include "CryptoLog/XTEA_CBC.h"
using namespace std;

int main()
{
  try
  {
    /* it is not a good idea to hard code the key like that! */
    const unsigned char key[] = { 0x01, 0x02, 0x03, 0x04,
                                  0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0A, 0x0B, 0x0C,
                                  0x0D, 0x0E, 0x0F, 0x10
                                };

    /* Blowfish CBC mode 128 bit key */
    CryptoLog::Blowfish_CBC log_bfcbc("bfcbc.log");
    log_bfcbc.set_key(key, 128);

    log_bfcbc.write("The quick brown fox jumps over the lazy dog");
    cout << log_bfcbc.get_plain_text() << endl;

    /* Blowfish CFB mode 128 bit key */
    CryptoLog::Blowfish_CFB log_bfcfb("bfcfb.log", key, 128);

    log_bfcfb.write("The quick brown fox jumps over the lazy dog");
    cout << log_bfcfb.get_plain_text() << endl;

    /* Blowfish CTR mode 128 bit key */
    CryptoLog::Blowfish_CTR log_bfctr("bfctr.log", key, 128);

    log_bfctr.write("The quick brown fox jumps over the lazy dog");
    cout << log_bfctr.get_plain_text() << endl;

    /* XTEA CBC mode */
    CryptoLog::XTEA_CBC log_xtea("xtea.log");
    log_xtea.set_key(key);

    log_xtea.write("The quick brown fox jumps over the lazy dog");
    cout << log_xtea.get_plain_text() << endl;

    return 0;
  }
  catch (exception &e)
  {
    cerr << e.what() << endl;
    return 1;
  }
  catch (...)
  {
    cerr << "Something went wrong!" << endl;
    return 1;
  }
}

