#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern int32_t carve_duration_charge(int32_t minutes,int32_t member);
__attribute__((noinline,used)) int32_t quoted_total(int32_t minutes,int32_t member,int32_t zone) {
  int32_t amount=carve_duration_charge(minutes,member);
  if (amount<0) return amount;
  return amount+(zone!=0?7:0);
}
int main(int argc,char **argv) {
  if (argc!=4) {fprintf(stderr,"split quote needs minutes membership and zone\n");return 2;}
  printf("%d\n",quoted_total(atoi(argv[1]),atoi(argv[2]),atoi(argv[3])));
  return 0;
}
