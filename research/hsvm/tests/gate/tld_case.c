// Gate case for ISA v2: Tld reads a word from the host table.
//
// Bytecode: tld r0, r0 + 0   (0x10) -> r0 = table32[r0]
//           halt             (0x0F)
// Both instructions are 8 bytes: [op][dst][a][b][imm u32 LE].
#include <stdint.h>
#include <stdio.h>

__attribute__((used, section("__DATA,__hsvm"))) const unsigned char hsvm_bytecode[] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t table_buf[64];
void *hsvm_table = table_buf;
unsigned long long hsvm_table_len = 64;

int32_t hsvm_entry(int32_t off);

int main(void) {
  for (int i = 0; i < 64; ++i) table_buf[i] = (uint8_t)(i * 7 + 1);
  int32_t got = hsvm_entry(8);
  uint32_t want = (uint32_t)table_buf[8] | ((uint32_t)table_buf[9] << 8) |
                  ((uint32_t)table_buf[10] << 16) |
                  ((uint32_t)table_buf[11] << 24);
  printf("tld hit    : got=0x%08x want=0x%08x %s\n", (uint32_t)got, want,
         (uint32_t)got == want ? "PASS" : "FAIL");
  int32_t bad = hsvm_entry(62);  // 62+4 > 64: must fault
  printf("tld oob    : got=0x%08x %s\n", (uint32_t)bad,
         (uint32_t)bad == 0xFFFFFFFEu ? "PASS" : "FAIL");
  int32_t mis = hsvm_entry(2);  // not 4-byte aligned: must fault
  printf("tld unalign: got=0x%08x %s\n", (uint32_t)mis,
         (uint32_t)mis == 0xFFFFFFFEu ? "PASS" : "FAIL");
  return 0;
}
