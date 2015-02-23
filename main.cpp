#include <iostream>
#include "CryptoLog_Blowfish_CBC.h"
#include "CryptoLog_Blowfish_CFB.h"
#include "CryptoLog_XTEA_CBC.h"
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
    CryptoLog_Blowfish_CBC log_bfcbc("bfcbc.log");
    log_bfcbc.set_key(key, 128);

    log_bfcbc.write("The quick brown fox jumps over the lazy dog");
    cout << log_bfcbc.get_plain_text() << endl;

    /* Blowfish CFB mode 128 bit key */
    CryptoLog_Blowfish_CFB log_bfcfb("bfcfb.log");
    log_bfcfb.set_key(key, 128);

    log_bfcfb.write("The quick brown fox jumps over the lazy dog");
    cout << log_bfcfb.get_plain_text() << endl;

    /* XTEA CBC mode */
    CryptoLog_XTEA_CBC log_xtea("xtea.log");
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

