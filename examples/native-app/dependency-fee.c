#include <stdio.h>
#include <stdlib.h>

/* Source-owned dependency fixture; only the compiled image is given to REA. */
__attribute__((noinline, used)) int fee_blocks(int minutes) {
  return (minutes + 14) / 15;
}

__attribute__((noinline, used)) int fee_discount(int amount, int member) {
  if (member) amount = amount * 8 / 10;
  return amount > 300 ? 300 : amount;
}

__attribute__((noinline, used)) int feature_fee(int minutes, int member) {
  if (minutes < 0) return -1;
  if (minutes <= 15) return 0;
  return fee_discount(fee_blocks(minutes) * 25, member);
}

__attribute__((noinline, used)) int fee_callback(int amount, int (*callback)(int)) {
  return callback(amount) + 1;
}

__attribute__((noinline, used)) int fee_notice(void) {
  return puts("local fee receipt");
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  printf("%d\n", feature_fee(atoi(argv[1]), atoi(argv[2])));
  return 0;
}
