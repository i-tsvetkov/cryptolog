#pragma once
#include <string>
#include <vector>
#include "polarssl/pkcs5.h"

using namespace std;

namespace CryptoLog {
  vector<unsigned char> generate_key(string salt, string password, size_t keylen);
}

vector<unsigned char> CryptoLog::generate_key(string salt,
                                              string password,
                                              size_t keylen)
{
  vector<unsigned char> key(keylen);

  md_context_t sha1_ctx;
  const md_info_t *info_sha1 = md_info_from_type(POLARSSL_MD_SHA1);

  md_init(&sha1_ctx);
  md_init_ctx(&sha1_ctx, info_sha1);

  pkcs5_pbkdf2_hmac(&sha1_ctx, (const unsigned char*) password.data(), password.size(),
                    (const unsigned char*) salt.data(), salt.size(), 1 << 12, keylen, key.data());

  md_free(&sha1_ctx);

  return key;
}

