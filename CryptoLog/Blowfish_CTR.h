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
  class Blowfish_CTR : public CryptoLog {
    public:
      Blowfish_CTR();
      Blowfish_CTR(const string &filename, const unsigned char key[], unsigned int keylen);
      Blowfish_CTR(const string &filename, const vector<unsigned char> &key);
      ~Blowfish_CTR();
      virtual void open(const string &filename);
      virtual void close();
      void set_key(const unsigned char key[], unsigned int keylen);
      void set_key(const vector<unsigned char> &key);
      virtual void write(const string &str);
      virtual string read();
      virtual string get_plain_text();
      virtual CryptoLog& operator<<(const string &str);
    private:
      blowfish_context ctx;
      string filename;
      unsigned char nonce_counter[BLOWFISH_BLOCKSIZE];
      unsigned char stream_block[BLOWFISH_BLOCKSIZE];
      size_t nc_off;
      void init_nc_and_offset();
      FILE *fp = NULL;
  };
}

CryptoLog::Blowfish_CTR::Blowfish_CTR()
{
  blowfish_init(&ctx);
}

CryptoLog::Blowfish_CTR::Blowfish_CTR(const string &filename,
                                      const unsigned char key[],
                                      unsigned int keylen)
{
  blowfish_init(&ctx);
  set_key(key, keylen);
  open(filename);
}

CryptoLog::Blowfish_CTR::Blowfish_CTR(const string &filename,
                                      const vector<unsigned char> &key)
{
  blowfish_init(&ctx);
  set_key(key.data(), key.size() * 8);
  open(filename);
}

CryptoLog::Blowfish_CTR::~Blowfish_CTR()
{
  close();
  blowfish_free(&ctx);
}

void CryptoLog::Blowfish_CTR::close()
{
  if (fp == NULL)
    return;

  blowfish_crypt_ecb(&ctx, BLOWFISH_ENCRYPT, stream_block, stream_block);

  fseek(fp, BLOWFISH_BLOCKSIZE / 2, SEEK_SET);

  fwrite(nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fwrite(stream_block, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
  fwrite(&nc_off, sizeof(size_t), 1, fp);

  fclose(fp);
  fp = NULL;
}

void CryptoLog::Blowfish_CTR::open(const string &filename)
{
  close();
  this->filename = filename;
  init_nc_and_offset();

  fp = fopen(filename.c_str(), "rb+");
  if (fp == NULL)
    throw runtime_error("Could not open file: " + filename);
}

void CryptoLog::Blowfish_CTR::set_key(const unsigned char key[], unsigned int keylen)
{
  if (keylen >= BLOWFISH_MIN_KEY && keylen <= BLOWFISH_MAX_KEY)
    blowfish_setkey(&ctx, key, keylen);
  else
    throw runtime_error("Invalid key length");
}

void CryptoLog::Blowfish_CTR::set_key(const vector<unsigned char> &key)
{
  set_key(key.data(), key.size() * 8);
}

void CryptoLog::Blowfish_CTR::init_nc_and_offset()
{
  if (file_exist(filename))
  {
    if (file_byte_size(filename) < 2 * BLOWFISH_BLOCKSIZE
                                   + BLOWFISH_BLOCKSIZE / 2
                                   + sizeof(size_t))
      throw runtime_error("File seems corrupted: " + filename);

    FILE *fp = fopen(filename.c_str(), "rb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    fseek(fp, BLOWFISH_BLOCKSIZE / 2, SEEK_SET);

    fread(nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fread(stream_block, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);

    blowfish_crypt_ecb(&ctx, BLOWFISH_DECRYPT, stream_block, stream_block);

    fread(&nc_off, sizeof(size_t), 1, fp);

    fclose(fp);
  }
  else
  {
    nc_off = 0;
    FILE *fp = fopen(filename.c_str(), "wb");
    if (fp == NULL)
      throw runtime_error("Could not open file: " + filename);

    memset(nonce_counter, 0, BLOWFISH_BLOCKSIZE);
    random_data(nonce_counter, BLOWFISH_BLOCKSIZE / 2);

    fwrite(nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE / 2, fp);

    fwrite(nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);
    fwrite(nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE, fp);

    fwrite(&nc_off, sizeof(size_t), 1, fp);

    fclose(fp);
  }
}

void CryptoLog::Blowfish_CTR::write(const string &str)
{
  size_t buff_size = str.size();
  unsigned char *out_buff = (unsigned char*) malloc(buff_size);

  blowfish_crypt_ctr(&ctx, buff_size, &nc_off, nonce_counter, stream_block,
                        (const unsigned char*) str.data(), out_buff);

  fseek(fp, 0, SEEK_END);
  fwrite(out_buff, sizeof(unsigned char), buff_size, fp);

  free(out_buff);
}

string CryptoLog::Blowfish_CTR::get_plain_text()
{
  fflush(fp);

  unsigned char *in_buff, *out_buff,
                first_nonce_counter[BLOWFISH_BLOCKSIZE],
                first_stream_block[BLOWFISH_BLOCKSIZE];

  size_t buff_size = file_byte_size(filename) - 2 * BLOWFISH_BLOCKSIZE
                                              - BLOWFISH_BLOCKSIZE / 2
                                              - sizeof(size_t);
  size_t first_nc_off = 0;

  in_buff  = (unsigned char*) malloc(buff_size);
  out_buff = (unsigned char*) malloc(buff_size + 1);
  memset(first_nonce_counter, 0, BLOWFISH_BLOCKSIZE);

  rewind(fp);
  fread(first_nonce_counter, sizeof(unsigned char), BLOWFISH_BLOCKSIZE / 2, fp);
  fseek(fp, 2 * BLOWFISH_BLOCKSIZE + sizeof(size_t), SEEK_CUR);
  fread(in_buff, sizeof(unsigned char), buff_size, fp);

  blowfish_crypt_ctr(&ctx, buff_size, &first_nc_off, first_nonce_counter, first_stream_block,
                      in_buff, out_buff);

  out_buff[buff_size] = '\0';
  string plaintext(reinterpret_cast<char*>(out_buff));

  free(in_buff);
  free(out_buff);

  return plaintext;
}

string CryptoLog::Blowfish_CTR::read()
{
  return get_plain_text();
}

CryptoLog::CryptoLog& CryptoLog::Blowfish_CTR::operator<<(const string &str)
{
  write(str);
  return *this;
}

