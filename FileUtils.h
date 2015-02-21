#pragma once
#include <cstdio>
#include <string>
using namespace std;

bool file_exist(const string &name)
{
  FILE *fp = fopen(name.c_str(), "rb");
  if (fp != NULL)
  {
    fclose(fp);
    return true;
  }
  else
    return false;
}

long int file_byte_size(const string &name)
{
  long int size = -1;
  FILE *fp = fopen(name.c_str(), "rb");
  if (fp == NULL)
    return size;
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fclose(fp);
  return size;
}

