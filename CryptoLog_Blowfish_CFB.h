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

class CryptoLog_Blowfish_CFB : public CryptoLog {
  public:
    CryptoLog_Blowfish_CFB();
    CryptoLog_Blowfish_CFB(const string &filename);
    ~CryptoLog_Blowfish_CFB();
    virtual void open(const string &filename);
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
};

CryptoLog_Blowfish_CFB::CryptoLog_Blowfish_CFB()
{
  blowfish_init(&ctx);
}

CryptoLog_Blowfish_CFB::CryptoLog_Blowfish_CFB(const string &filename)
{
  blowfish_init(&ctx);
  this->open(filename);
}

CryptoLog_Blowfish_CFB::~CryptoLog_Blowfish_CFB()
{
  blowfish_free(&ctx);
}

void CryptoLog_Blowfish_CFB::open(const string &filename)
{
  this->filename = filename;
  init_iv_and_offset();
}

void CryptoLog_Blowfish_CFB::set_key(const unsigned char key[], unsigned int keylen)
{
  if (keylen >= BLOWFISH_MIN_KEY && keylen <= BLOWFISH_MAX_KEY)
    blowfish_setkey(&ctx, key, keylen);
  else
    throw runtime_error("Invalid key length");
}

void CryptoLog_Blowfish_CFB::init_iv_and_offset()
{
  if (file_exist(filename))
  {
    if (file_byte_size(filename) < BLOWFISH_BLOCKSIZE + sizeof(size_t))
      throw runtime_error("File seems corrupted: " + filename);

    FILE *fp = fopen(filename.c_str(), "rb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);
    fseek(fp, - BLOWFISH_BLOCKSIZE - sizeof(size_t), SEEK_END);
    fread(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fread(&iv_off, sizeof(size_t), 1, fp);
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

void CryptoLog_Blowfish_CFB::write(const string &str)
{
  unsigned char *in_buff, *out_buff;
  size_t buff_size = str.size();

  FILE *fp = fopen(filename.c_str(), "rb+");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);

  in_buff  = (unsigned char*) calloc(1, buff_size);
  out_buff = (unsigned char*) calloc(1, buff_size);

  memcpy(in_buff, str.c_str(), str.size());

  blowfish_crypt_cfb64(&ctx, BLOWFISH_ENCRYPT, buff_size, &iv_off, iv, in_buff, out_buff);

  fseek(fp, - BLOWFISH_BLOCKSIZE - sizeof(size_t), SEEK_END);

  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  fwrite(iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fwrite(&iv_off, sizeof(size_t), 1, fp);

  free(in_buff);
  free(out_buff);
  fclose(fp);
}

string CryptoLog_Blowfish_CFB::get_plain_text()
{
  unsigned char *in_buff, *out_buff, first_iv[BLOWFISH_BLOCKSIZE];
  size_t buff_size = file_byte_size(filename) - 2 * BLOWFISH_BLOCKSIZE - sizeof(size_t);
  size_t first_iv_off = 0;

  FILE *fp = fopen(filename.c_str(), "rb");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size);

  fread(first_iv, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);
  fclose(fp);

  blowfish_crypt_cfb64(&ctx, BLOWFISH_DECRYPT, buff_size, &first_iv_off, first_iv, in_buff, out_buff);

  string plaintext("");
  for (int i = 0; i < buff_size; i++)
    if (out_buff[i] != 0x00)
      plaintext += (char) out_buff[i];

  free(in_buff);
  free(out_buff);

  return plaintext;
}

string CryptoLog_Blowfish_CFB::read()
{
  return this->get_plain_text();
}
