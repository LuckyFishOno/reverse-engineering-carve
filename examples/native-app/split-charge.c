#include <stdint.h>
/* Owned fixture: actual dynamic-library code; no original source is sent to Ghidra. */
__attribute__((noinline,visibility("default"))) int32_t carve_duration_charge(int32_t minutes,int32_t member) {
  if (minutes<0) return -1;
  if (minutes<=15) return 0;
  uint32_t blocks=((uint32_t)minutes+14u)/15u;
  uint32_t amount=blocks*(member!=0?20u:25u);
  return amount>300u?300:(int32_t)amount;
}
