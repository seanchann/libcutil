#include <sys/select.h>
#include <stdio.h>


int main(int argc, const char *argv[])
{
  fd_set foo;
  printf("%d", sizeof(foo.fds_bits[0]));
  return 1;
}
