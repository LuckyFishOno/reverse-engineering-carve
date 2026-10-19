#include <stdio.h>
#include <stdlib.h>
/* Source-owned regression input. Its source is not passed to decompilation. */
__attribute__((noinline,used)) int parking_fee(int minutes, int member) {
  if (minutes < 0) return -1;
  if (minutes <= 15) return 0;
  int blocks = (minutes + 14) / 15;
  int fee = blocks * 25;
  if (member) fee = fee * 8 / 10;
  return fee > 300 ? 300 : fee;
}
__attribute__((noinline,used)) int unrelated_editor(int value) { return value * 99; }
int main(int argc, char **argv) {
  if (argc != 3) { fprintf(stderr, "parking fee needs minutes and membership\n"); return 2; }
  printf("%d\n", parking_fee(atoi(argv[1]), atoi(argv[2])));
  return 0;
}
