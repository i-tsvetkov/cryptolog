#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cmath>
#include <stdexcept>
#include "CryptoLog.h"
#include "FileUtils.h"
#include "Random.h"
#include "polarssl/blowfish.h"

using namespace std;

namespace CryptoLog {
  class Blowfish_CBC : public CryptoLog {
    public:
      Blowfish_CBC();
      Blowfish_CBC(const string &filename);
      ~Blowfish_CBC();
      virtual void open(const string &filename);
      virtual void close();
      void set_key(const unsigned char key[], unsigned int keylen);
      virtual void write(const string &str);
      virtual string read();
      virtual string get_plain_text();
    private:
      blowfish_context ctx;
      string filename;
      unsigned char iv[BLOWFISH_BLOCKSIZE];
      void init_iv();
      FILE *fp;
  };
}

CryptoLog::Blowfish_CBC::Blowfish_CBC()
{
  blowfish_init(&ctx);
  fp = NULL;
}

CryptoLog::Blowfish_CBC::Blowfish_CBC(const string &filename)
{
  blowfish_init(&ctx);
  fp = NULL;
  this->open(filename);
}

CryptoLog::Blowfish_CBC::~Blowfish_CBC()
{
  blowfish_free(&ctx);
  this->close();
}

void CryptoLog::Blowfish_CBC::close()
{
  if (fp == NULL)
    return;

  fclose(fp);
  fp = NULL;
}

void CryptoLog::Blowfish_CBC::open(const string &filename)
{
  this->close();
  this->filename = filename;
  init_iv();

  fp = fopen(filename.c_str(), "ab+");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);
}

void CryptoLog::Blowfish_CBC::init_iv()
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

    random_data(iv, BLOWFISH_BLOCKSIZE);

    fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fclose(fp);
  }
}

void CryptoLog::Blowfish_CBC::set_key(const unsigned char key[], unsigned int keylen)
{
  if (keylen >= BLOWFISH_MIN_KEY && keylen <= BLOWFISH_MAX_KEY)
    blowfish_setkey(&ctx, key, keylen);
  else
    throw runtime_error("Invalid key length");
}

void CryptoLog::Blowfish_CBC::write(const string &str)
{
  unsigned char *in_buff, *out_buff;
  size_t buff_size = BLOWFISH_BLOCKSIZE * ceil((str.size() + 1.0) / BLOWFISH_BLOCKSIZE);

  in_buff  = (unsigned char*) calloc(1, buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  memcpy(in_buff, str.c_str(), str.size());

  blowfish_crypt_cbc(&ctx, BLOWFISH_ENCRYPT, buff_size, iv, in_buff, out_buff);

  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  free(in_buff);
  free(out_buff);
}

string CryptoLog::Blowfish_CBC::get_plain_text()
{
  fflush(fp);

  unsigned char *in_buff, *out_buff, first_iv[BLOWFISH_BLOCKSIZE];
  size_t buff_size = file_byte_size(filename) - BLOWFISH_BLOCKSIZE;

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  rewind(fp);
  fread(first_iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);

  blowfish_crypt_cbc(&ctx, BLOWFISH_DECRYPT, buff_size, first_iv, in_buff, out_buff);

  string plaintext("");
  for (int i = 0; i < buff_size; i++)
    if (out_buff[i] != 0x00)
      plaintext += (char) out_buff[i];

  free(in_buff);
  free(out_buff);

  return plaintext;
}

string CryptoLog::Blowfish_CBC::read()
{
  return this->get_plain_text();
}
