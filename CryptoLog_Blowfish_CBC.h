#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cmath>
#include <stdexcept>
#include "CryptoLog.h"
#include "FileUtils.h"
#include "polarssl/blowfish.h"

using namespace std;

class CryptoLog_Blowfish_CBC : public CryptoLog {
  public:
    CryptoLog_Blowfish_CBC();
    CryptoLog_Blowfish_CBC(const string &filename);
    ~CryptoLog_Blowfish_CBC();
    virtual void open(const string &filename);
    void set_key(const unsigned char key[], unsigned int keylen);
    virtual void write(const string &str);
    virtual string get_plain_text();
  private:
    blowfish_context ctx;
    string filename;
    unsigned char iv[BLOWFISH_BLOCKSIZE];
    void init_iv();
};

CryptoLog_Blowfish_CBC::CryptoLog_Blowfish_CBC()
{
  blowfish_init(&ctx);
}

CryptoLog_Blowfish_CBC::CryptoLog_Blowfish_CBC(const string &filename)
{
  blowfish_init(&ctx);
  this->open(filename);
}

CryptoLog_Blowfish_CBC::~CryptoLog_Blowfish_CBC()
{
  blowfish_free(&ctx);
}

void CryptoLog_Blowfish_CBC::open(const string &filename)
{
  this->filename = filename;
  init_iv();
}

void CryptoLog_Blowfish_CBC::init_iv()
{
  if (file_exist(filename))
  {
    if (file_byte_size(filename) < BLOWFISH_BLOCKSIZE)
      throw runtime_error("File seems corrupted: " + filename);

    FILE *fp = fopen(filename.c_str(), "rb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);
    fseek(fp, -BLOWFISH_BLOCKSIZE, SEEK_END);
    fread(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fclose(fp);
  }
  else
  {
    FILE *fp = fopen(filename.c_str(), "wb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    srand(time(NULL));

    for(int i = 0; i < BLOWFISH_BLOCKSIZE; i++)
      iv[i] = (unsigned char) rand();

    fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fclose(fp);
  }
}

void CryptoLog_Blowfish_CBC::set_key(const unsigned char key[], unsigned int keylen)
{
  if (keylen >= BLOWFISH_MIN_KEY && keylen <= BLOWFISH_MAX_KEY)
    blowfish_setkey(&ctx, key, keylen);
  else
    throw runtime_error("Invalid key length");
}

void CryptoLog_Blowfish_CBC::write(const string &str)
{
  unsigned char *in_buff, *out_buff;
  size_t buff_size = BLOWFISH_BLOCKSIZE * ceil((str.size() + 1.0) / BLOWFISH_BLOCKSIZE);

  FILE *fp = fopen(filename.c_str(), "ab");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);

  in_buff  = (unsigned char*) calloc(1, buff_size);
  out_buff = (unsigned char*) calloc(1, buff_size);

  memcpy(in_buff, str.c_str(), str.size());

  blowfish_crypt_cbc(&ctx, BLOWFISH_ENCRYPT, buff_size, iv, in_buff, out_buff);

  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  free(in_buff);
  free(out_buff);
  fclose(fp);
}

string CryptoLog_Blowfish_CBC::get_plain_text()
{
  unsigned char *in_buff, *out_buff, first_iv[BLOWFISH_BLOCKSIZE];
  size_t buff_size = file_byte_size(filename) - BLOWFISH_BLOCKSIZE;

  FILE *fp = fopen(filename.c_str(), "rb");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  fread(first_iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);
  fclose(fp);

  blowfish_crypt_cbc(&ctx, BLOWFISH_DECRYPT, buff_size, first_iv, in_buff, out_buff);

  string plaintext("");
  for (int i = 0; i < buff_size; i++)
    if (out_buff[i] != 0x00)
      plaintext += (char) out_buff[i];

  free(in_buff);
  free(out_buff);

  return plaintext;
}
