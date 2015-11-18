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
#include "polarssl/blowfish.h"

using namespace std;

namespace CryptoLog {
  class Blowfish_CFB : public CryptoLog {
    public:
      Blowfish_CFB();
      Blowfish_CFB(const string &filename, const unsigned char key[], unsigned int keylen);
      Blowfish_CFB(const string &filename, const vector<unsigned char> &key);
      ~Blowfish_CFB();
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
      size_t iv_off;
      void init_iv_and_offset();
      FILE *fp = NULL;
  };
}

CryptoLog::Blowfish_CFB::Blowfish_CFB()
{
  blowfish_init(&ctx);
}

CryptoLog::Blowfish_CFB::Blowfish_CFB(const string &filename,
                                      const unsigned char key[],
                                      unsigned int keylen)
{
  blowfish_init(&ctx);
  set_key(key, keylen);
  open(filename);
}

CryptoLog::Blowfish_CFB::Blowfish_CFB(const string &filename,
                                      const vector<unsigned char> &key)
{
  blowfish_init(&ctx);
  set_key(key.data(), key.size() * 8);
  open(filename);
}

CryptoLog::Blowfish_CFB::~Blowfish_CFB()
{
  close();
  blowfish_free(&ctx);
}

void CryptoLog::Blowfish_CFB::close()
{
  if (fp == NULL)
    return;

  random_data(iv, iv_off);
  blowfish_crypt_ecb(&ctx, BLOWFISH_ENCRYPT, iv, iv);

  fseek(fp, BLOWFISH_BLOCKSIZE, SEEK_SET);

  fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fwrite(&iv_off, sizeof(size_t), 1, fp);

  fclose(fp);
  fp = NULL;
}

void CryptoLog::Blowfish_CFB::open(const string &filename)
{
  close();
  this->filename = filename;
  init_iv_and_offset();

  fp = fopen(filename.c_str(), "rb+");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);
}

void CryptoLog::Blowfish_CFB::set_key(const unsigned char key[], unsigned int keylen)
{
  if (keylen >= BLOWFISH_MIN_KEY && keylen <= BLOWFISH_MAX_KEY)
    blowfish_setkey(&ctx, key, keylen);
  else
    throw runtime_error("Invalid key length");
}

void CryptoLog::Blowfish_CFB::init_iv_and_offset()
{
  if (file_exist(filename))
  {
    if (file_byte_size(filename) < 2 * BLOWFISH_BLOCKSIZE + sizeof(size_t))
      throw runtime_error("File seems corrupted: " + filename);

    FILE *fp = fopen(filename.c_str(), "rb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    fseek(fp, BLOWFISH_BLOCKSIZE, SEEK_SET);

    fread(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fread(&iv_off, sizeof(size_t), 1, fp);

    blowfish_crypt_ecb(&ctx, BLOWFISH_DECRYPT, iv, iv);

    fseek(fp, -iv_off, SEEK_END);
    fread(iv, sizeof(unsigned char), iv_off, fp);

    fclose(fp);
  }
  else
  {
    iv_off = 0;
    FILE *fp = fopen(filename.c_str(), "wb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    random_data(iv, BLOWFISH_BLOCKSIZE);

    fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fwrite(&iv_off, sizeof(size_t), 1, fp);
    fclose(fp);
  }
}

void CryptoLog::Blowfish_CFB::write(const string &str)
{
  size_t buff_size = str.size();
  unsigned char *out_buff = (unsigned char*) malloc(buff_size);

  blowfish_crypt_cfb64(&ctx, BLOWFISH_ENCRYPT, buff_size, &iv_off, iv,
                        (const unsigned char*) str.data(), out_buff);

  fseek(fp, 0, SEEK_END);
  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  free(out_buff);
}

string CryptoLog::Blowfish_CFB::get_plain_text()
{
  fflush(fp);

  unsigned char *in_buff, *out_buff, first_iv[BLOWFISH_BLOCKSIZE];
  size_t buff_size = file_byte_size(filename) - 2 * BLOWFISH_BLOCKSIZE - sizeof(size_t);
  size_t first_iv_off = 0;

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size + 1);

  rewind(fp);
  fread(first_iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fseek(fp, BLOWFISH_BLOCKSIZE + sizeof(size_t), SEEK_CUR);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);

  blowfish_crypt_cfb64(&ctx, BLOWFISH_DECRYPT, buff_size, &first_iv_off, first_iv, in_buff, out_buff);

  out_buff[buff_size] = '\0';
  string plaintext(reinterpret_cast<char*>(out_buff));

  free(in_buff);
  free(out_buff);

  return plaintext;
}

string CryptoLog::Blowfish_CFB::read()
{
  return get_plain_text();
}
