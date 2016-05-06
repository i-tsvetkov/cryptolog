#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cmath>
#include <stdexcept>
#include <vector>
#include "CryptoLog.h"
#include "FileUtils.h"
#include "Random.h"
#include "polarssl/xtea.h"

using namespace std;

/*  8 bytes ==  64 bits */
#define XTEA_BLOCK_SIZE 8
/* 16 bytes == 128 bits */
#define XTEA_KEY_SIZE  16

namespace CryptoLog {
  class XTEA_CBC : public CryptoLog {
    public:
      XTEA_CBC();
      XTEA_CBC(const string &filename);
      XTEA_CBC(const string &filename, const unsigned char key[XTEA_KEY_SIZE]);
      XTEA_CBC(const string &filename, const vector<unsigned char> &key);
      ~XTEA_CBC();
      virtual void open(const string &filename);
      virtual void close();
      void set_key(const unsigned char key[XTEA_KEY_SIZE]);
      void set_key(const vector<unsigned char> &key);
      virtual void write(const string &str);
      virtual string read();
      virtual string get_plain_text();
      virtual CryptoLog& operator<<(const string &str);
    private:
      xtea_context ctx;
      string filename;
      unsigned char iv[XTEA_BLOCK_SIZE];
      void init_iv();
      FILE *fp = NULL;
  };
}

CryptoLog::XTEA_CBC::XTEA_CBC()
{
  xtea_init(&ctx);
}

CryptoLog::XTEA_CBC::XTEA_CBC(const string &filename)
{
  xtea_init(&ctx);
  open(filename);
}

CryptoLog::XTEA_CBC::XTEA_CBC(const string &filename,
                              const unsigned char key[XTEA_KEY_SIZE])
{
  xtea_init(&ctx);
  set_key(key);
  open(filename);
}

CryptoLog::XTEA_CBC::XTEA_CBC(const string &filename,
                              const vector<unsigned char> &key)
{
  xtea_init(&ctx);
  set_key(key.data());
  open(filename);
}

CryptoLog::XTEA_CBC::~XTEA_CBC()
{
  close();
  xtea_free(&ctx);
}

void CryptoLog::XTEA_CBC::close()
{
  if (fp == NULL)
    return;

  fclose(fp);
  fp = NULL;
}

void CryptoLog::XTEA_CBC::init_iv()
{
  if (file_exist(filename))
  {
    if (file_byte_size(filename) < XTEA_BLOCK_SIZE)
      throw runtime_error("File seems corrupted: " + filename);

    FILE *fp = fopen(filename.c_str(), "rb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);
    fseek(fp, -XTEA_BLOCK_SIZE, SEEK_END);
    fread(iv, sizeof(unsigned char), XTEA_BLOCK_SIZE, fp);
    fclose(fp);
  }
  else
  {
    FILE *fp = fopen(filename.c_str(), "wb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    random_data(iv, XTEA_BLOCK_SIZE);

    fwrite(iv, sizeof(unsigned char), XTEA_BLOCK_SIZE, fp);
    fclose(fp);
  }
}

void CryptoLog::XTEA_CBC::open(const string &filename)
{
  close();
  this->filename = filename;
  init_iv();

  fp = fopen(filename.c_str(), "ab+");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);
}

void CryptoLog::XTEA_CBC::set_key(const unsigned char key[XTEA_KEY_SIZE])
{
  xtea_setup(&ctx, key);
}

void CryptoLog::XTEA_CBC::set_key(const vector<unsigned char> &key)
{
  set_key(key.data());
}

void CryptoLog::XTEA_CBC::write(const string &str)
{
  unsigned char *in_buff, *out_buff;
  size_t buff_size = XTEA_BLOCK_SIZE * ceil((str.size() + 1.0) / XTEA_BLOCK_SIZE);

  in_buff  = (unsigned char*) calloc(1, buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  memcpy(in_buff, str.c_str(), str.size());

  xtea_crypt_cbc(&ctx, XTEA_ENCRYPT, buff_size, iv, in_buff, out_buff);

  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  free(in_buff);
  free(out_buff);
}

string CryptoLog::XTEA_CBC::get_plain_text()
{
  fflush(fp);

  unsigned char *in_buff, *out_buff, first_iv[XTEA_BLOCK_SIZE];
  size_t buff_size = file_byte_size(filename) - XTEA_BLOCK_SIZE;

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  rewind(fp);
  fread(first_iv, sizeof(unsigned char), XTEA_BLOCK_SIZE, fp);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);

  xtea_crypt_cbc(&ctx, XTEA_DECRYPT, buff_size, first_iv, in_buff, out_buff);

  string plaintext("");
  for (int i = 0; i < buff_size; i++)
    if (out_buff[i] != 0x00)
      plaintext += (char) out_buff[i];

  free(in_buff);
  free(out_buff);

  return plaintext;
}

string CryptoLog::XTEA_CBC::read()
{
  return get_plain_text();
}

CryptoLog::CryptoLog& CryptoLog::XTEA_CBC::operator<<(const string &str)
{
  write(str);
  return *this;
}

