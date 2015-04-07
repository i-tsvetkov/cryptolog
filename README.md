# CryptoLog
simple classes implementing log file protected with
cryptographic ciphers

### Supported ciphers and their modes
  * XTEA / CBC
  * Blowfish / CBC
  * Blowfish / CFB

## API
```c++
// constructor that opens / creates a log file for writing
CryptoLog(const string &filename);

// opens / creates a log file; closing is automatic
virtual void open(const string &filename);

// sets the encryption key and its length
void set_key(const unsigned char key[], unsigned int keylen);

// writes string to the file
virtual void write(const string &str);

// returns the decrypted file content
virtual string get_plain_text(void);
```

## Example of the API
```c++
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

```

