// wbaes_vm.cpp — the HSV bytecode program that computes the white-box table
// offsets, plus the host entry points around it.
//
// Compile this translation unit with `-mllvm -passes=hsvm` (see README §12).
// The pass reads @hsvm_bytecode, refuses anything outside ISA v2, and replaces
// the body of hsvm_entry with the lowered program: one basic block per
// instruction, direct branches, no opcode fetch and no dispatch loop.
//
// What one call computes:
//   arg  = (dir << 8) | (round << 4) | i            (dir 0 = encrypt, 1 = decrypt)
//   fam  = schedule block byte at (dir * 16 + round), read with Tld
//   off  = base[dir] + round * round_stride[dir] + (i >> 2) * col_stride
//          + lane stride of family `fam` for lane (i & 3)
//   the offset is stored back into VM memory (St) and returned in r0.
//
// Every input comes from the table itself: the family byte says which shape the
// round uses, and the layout words (32..59 of the schedule block) say how wide a
// column slot and a lane are. Nothing about the 69 MB layout is baked into the
// bytecode, so damaging the schedule block changes every offset the reader uses.
//
// Schedule block layout (64 B, masked and sealed with the rest of the table):
//   [ 0.. 8] encrypt families        [ 9] encrypt check byte
//   [16..24] decrypt families        [25] decrypt check byte
//   [32] encrypt base                [36] decrypt base
//   [40] encrypt round stride        [44] decrypt round stride
//   [48] column stride               [52] lane stride (F1/F2/F3)
//   [56] pair stride (F0, lanes 2..3)
//
// Instruction encoding (8 bytes): [op][dst][a][b][imm32 LE], ISA v2.
#include "wbaes_vm.h"

// The program: 43 instructions, 344 bytes, 16 registers, 4 KiB of VM memory.
// Every immediate is a schedule-block offset; the branches implement the two
// shape classes (pair lanes vs. one table per lane).
__attribute__((used, section("__DATA,__hsvm"))) extern "C" const unsigned char
    hsvm_bytecode[344] = {
        0x01, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //  0 movi r8, 3              lane mask (i & 3)
        0x01, 0x09, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, //  1 movi r9, 4              shift by 4
        0x01, 0x0a, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, //  2 movi r10, 12            schedule byte offset within the direction block
        0x01, 0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, //  3 movi r11, 15            nibble mask
        0x01, 0x0c, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, //  4 movi r12, 255           byte mask
        0x01, 0x0f, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //  5 movi r15, 2             shift by 2 (col, 4*i) and pair-lane test
        0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  6 mov  r1, r0             r1 = arg
        0x09, 0x01, 0x01, 0x09, 0x00, 0x00, 0x00, 0x00, //  7 shr  r1, r1, r9         r1 = (dir << 4) | round
        0x06, 0x02, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, //  8 and  r2, r1, r11        r2 = round
        0x09, 0x03, 0x01, 0x09, 0x00, 0x00, 0x00, 0x00, //  9 shr  r3, r1, r9         r3 = dir
        0x06, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, // 10 and  r4, r0, r11        r4 = i
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 11 movi r0, 0              r0 = 0, zero register for the fixed table offsets
        0x06, 0x05, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, // 12 and  r5, r4, r8         r5 = k = i & 3
        0x09, 0x06, 0x04, 0x0f, 0x00, 0x00, 0x00, 0x00, // 13 shr  r6, r4, r15        r6 = col = i >> 2
        0x08, 0x07, 0x03, 0x09, 0x00, 0x00, 0x00, 0x00, // 14 shl  r7, r3, r9         r7 = dir * 16
        0x06, 0x01, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, // 15 and  r1, r2, r10        r1 = round & 12
        0x03, 0x07, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, // 16 add  r7, r7, r1         r7 = byte offset of this round's schedule word
        0x10, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, // 17 tld  r7, r7+0           r7 = Table[r7+0]: four schedule bytes
        0x06, 0x01, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, // 18 and  r1, r2, r8         r1 = round & 3
        0x08, 0x01, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, // 19 shl  r1, r1, r8         r1 = 8 * (round & 3)
        0x09, 0x07, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, // 20 shr  r7, r7, r1         r7 >>= r1: this round's byte
        0x06, 0x07, 0x07, 0x0c, 0x00, 0x00, 0x00, 0x00, // 21 and  r7, r7, r12        r7 = family
        0x08, 0x0e, 0x03, 0x0f, 0x00, 0x00, 0x00, 0x00, // 22 shl  r14, r3, r15       r14 = 4 * dir
        0x10, 0x0d, 0x0e, 0x00, 0x20, 0x00, 0x00, 0x00, // 23 tld  r13, r14+32        r13 = base[dir]
        0x10, 0x01, 0x0e, 0x00, 0x28, 0x00, 0x00, 0x00, // 24 tld  r1, r14+40         r1 = round stride[dir]
        0x0a, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, // 25 mul  r1, r2, r1         r1 = round * stride
        0x03, 0x0d, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, // 26 add  r13, r13, r1       r13 += round * stride
        0x10, 0x01, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, // 27 tld  r1, r0+48          r1 = column stride
        0x0a, 0x01, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, // 28 mul  r1, r6, r1         r1 = col * column stride
        0x03, 0x0d, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, // 29 add  r13, r13, r1       r13 += col * column stride
        0x0e, 0x00, 0x07, 0x00, 0x05, 0x00, 0x00, 0x00, // 30 brz  r7, 35             family 0 uses the pair layout
        0x10, 0x01, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, // 31 tld  r1, r0+52          r1 = lane stride (F1/F2/F3)
        0x0a, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, // 32 mul  r1, r5, r1         r1 = k * lane stride
        0x03, 0x0d, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, // 33 add  r13, r13, r1       r13 += k * lane stride
        0x0d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // 34 jmp  39
        0x06, 0x01, 0x05, 0x0f, 0x00, 0x00, 0x00, 0x00, // 35 and  r1, r5, r15        r1 = k & 2
        0x0e, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, // 36 brz  r1, 39             k < 2: no pair offset
        0x10, 0x01, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, // 37 tld  r1, r0+56          r1 = pair stride
        0x03, 0x0d, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, // 38 add  r13, r13, r1       r13 += pair stride
        0x08, 0x01, 0x04, 0x0f, 0x00, 0x00, 0x00, 0x00, // 39 shl  r1, r4, r15        r1 = 4 * i
        0x0c, 0x00, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, // 40 st   Mem[r1], r13       Mem[4*i] = offset
        0x02, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, // 41 mov  r0, r13            r0 = offset
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 42 halt                    return r0
};

// Tld's view of host memory: the unmasked schedule block (Tld refuses a null
// pointer, a misaligned offset or a word that runs past the end).
extern "C" {
void *hsvm_table = nullptr;
unsigned long long hsvm_table_len = 0;
}

void hy_vm_set_table(const void *tab, uint64_t len) {
    hsvm_table = const_cast<void *>(tab);
    hsvm_table_len = len;
}

int hy_vm_offsets(int32_t dir, int32_t round, uint32_t off[16]) {
    for (int32_t i = 0; i < 16; i++) {
        const int32_t r = hsvm_entry((dir << 8) | (round << 4) | i);
        if (r < 0) {  // 0xFFFFFFFE fault / 0xFFFFFFFF pc out of range
            for (int32_t k = 0; k < 16; k++) off[k] = 0;
            return -1;
        }
        off[i] = (uint32_t)r;
    }
    return 0;
}
