#if _WIN32
#define _CRT_RAND_S
#endif
#include <stdlib.h>
#include <time.h>

void random_data(unsigned char *data, int len)
{
#if _WIN32
  unsigned char rand_num;
  static bool seed = true;
  if (seed)
  {
    srand((rand_s(&rand_num) == 0) ? rand_num : time(NULL));
    seed = false;
  }
  for (int i = 0; i < len; i++)
    data[i] = (rand_s(&rand_num) == 0) ? rand_num : (unsigned char) rand();
#elif __gnu_linux__
  FILE *fp = fopen("/dev/urandom", "rb");
  if (fp != NULL)
  {
    fread(data, len, sizeof(unsigned char), fp);
    fclose(fp);
  }
  else
  {
    static bool seed = true;
    if (seed)
    {
      srand(time(NULL));
      seed = false;
    }
    for (int i = 0; i < len; i++)
      data[i] = (unsigned char) rand();
  }
#else
  static bool seed = true;
  if (seed)
  {
    srand(time(NULL));
    seed = false;
  }
  for (int i = 0; i < len; i++)
    data[i] = (unsigned char) rand();
#endif
}

