// wbaes_vm.cpp — the HSV bytecode program that computes the white-box table
// offsets, plus the host entry points around it.
//
// Compile this translation unit with `-mllvm -passes=hsvm` (see README §5.28).
// The pass reads @hsvm_bytecode, refuses anything outside ISA v2, and replaces
// the body of hsvm_entry with the lowered program: one basic block per
// instruction, direct branches, no opcode fetch and no dispatch loop.
//
// What one call computes — the complete plan, not one offset:
//
//   for dir in 0,1:                     (0 = encrypt, 1 = decrypt)
//     for round in 0..8:
//       fam = schedule block byte at (dir * 16 + round), read with Tld
//       for i in 0..15:
//         off = base[dir] + round * round_stride[dir]
//             + (i >> 2) * col_stride + lane stride of family `fam` for lane (i & 3)
//         Mem[4 * (dir * 144 + round * 16 + i)] = off        (St, ISA v2)
//
// 288 offsets in one invocation. Every input comes from the table itself: the
// family byte says which shape the round uses, and the layout words (32..59 of
// the schedule block) say how wide a column slot and a lane are. Nothing about
// the 69 MB layout is baked into the bytecode, so damaging the schedule block
// changes every offset the reader uses.
//
// Why the whole plan and not one offset per call: the offsets depend only on the
// schedule block and the layout words, never on plaintext or key, so they are
// static per build. Asking the VM 288 times per block paid the VM's fixed cost
// (memory clear + register fill) 288 times for the same 288 numbers. One call
// per table load, cached by the host, is the same computation with the same
// inputs and the same answer. The nine-round table walk itself stays in C++: it
// reads 69 MB and is data-plane work, and moving a per-block loop into bytecode
// would gain nothing now that the offsets are static.
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

// The program: 61 instructions, 488 bytes, 16 registers, 4 KiB of VM memory.
// Every immediate is a schedule-block offset; the branches implement the two
// shape classes (pair lanes vs. one table per lane) and the three loops. The
// constants (3, 2, 0, 4) are built from Movi so that only four immediates drive
// all the addressing arithmetic; 1, 9, 12, 16 and 24 are derived from them.
__attribute__((used, section("__DATA,__hsvm"))) extern "C" const unsigned char
    hsvm_bytecode[488] = {
        0x01, 0x09, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //  0 movi r9, 3              lane mask (i & 3), round & 3
        0x01, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //  1 movi r10, 2             column shift, k & 2 test, dir limit
        0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  2 movi r11, 0             zero: base register for absolute words
        0x01, 0x0c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, //  3 movi r12, 4             store-address stride: one word
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  4 movi r2, 0              dir = 0
        0x10, 0x06, 0x0b, 0x00, 0x30, 0x00, 0x00, 0x00, //  5 tld  r6, r11+48         column stride (invariant)
        0x02, 0x03, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, //  6 mov  r3, r11            store address = 0
        0x02, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, //  7 mov  r1, r11            round = 0
        0x08, 0x0d, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, //  8 shl  r13, r2, r10       dir * 4
        0x08, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, //  9 shl  r13, r13, r10      dir * 16
        0x08, 0x0e, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00, // 10 shl  r14, r9, r10       12 = 3 << 2
        0x06, 0x0f, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x00, // 11 and  r15, r1, r14       round & 12
        0x03, 0x0d, 0x0d, 0x0f, 0x00, 0x00, 0x00, 0x00, // 12 add  r13, r13, r15      byte offset of this round's word
        0x10, 0x04, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, // 13 tld  r4, r13+0          four family bytes, one per round
        0x06, 0x0e, 0x01, 0x09, 0x00, 0x00, 0x00, 0x00, // 14 and  r14, r1, r9        round & 3
        0x08, 0x0e, 0x0e, 0x09, 0x00, 0x00, 0x00, 0x00, // 15 shl  r14, r14, r9       8 * (round & 3)
        0x08, 0x0f, 0x09, 0x09, 0x00, 0x00, 0x00, 0x00, // 16 shl  r15, r9, r9        24
        0x04, 0x0e, 0x0f, 0x0e, 0x00, 0x00, 0x00, 0x00, // 17 sub  r14, r15, r14      24 - 8 * (round & 3)
        0x08, 0x04, 0x04, 0x0e, 0x00, 0x00, 0x00, 0x00, // 18 shl  r4, r4, r14        move this round's byte to the top
        0x09, 0x04, 0x04, 0x0f, 0x00, 0x00, 0x00, 0x00, // 19 shr  r4, r4, r15        and down again: fam
        0x08, 0x0d, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, // 20 shl  r13, r2, r10       dir * 4
        0x10, 0x05, 0x0d, 0x00, 0x20, 0x00, 0x00, 0x00, // 21 tld  r5, r13+32         base[dir]
        0x10, 0x0d, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, // 22 tld  r13, r13+40        round stride[dir]
        0x0a, 0x0d, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, // 23 mul  r13, r1, r13       round * round stride
        0x03, 0x05, 0x05, 0x0d, 0x00, 0x00, 0x00, 0x00, // 24 add  r5, r5, r13        base + round * stride
        0x10, 0x07, 0x0b, 0x00, 0x34, 0x00, 0x00, 0x00, // 25 tld  r7, r11+52         lane stride (F1/F2/F3)
        0x10, 0x08, 0x0b, 0x00, 0x38, 0x00, 0x00, 0x00, // 26 tld  r8, r11+56         pair stride (F0, lanes 2,3)
        0x02, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // 27 mov  r0, r11            i = 0
        0x06, 0x0d, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, // 28 and  r13, r0, r9        k = i & 3
        0x09, 0x0e, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, // 29 shr  r14, r0, r10       col = i >> 2
        0x0a, 0x0e, 0x0e, 0x06, 0x00, 0x00, 0x00, 0x00, // 30 mul  r14, r14, r6       col * column stride
        0x03, 0x0e, 0x0e, 0x05, 0x00, 0x00, 0x00, 0x00, // 31 add  r14, r14, r5       + base + round * stride
        0x0e, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, // 32 brz  r4, 36             family 0 uses the pair layout
        0x0a, 0x0f, 0x0d, 0x07, 0x00, 0x00, 0x00, 0x00, // 33 mul  r15, r13, r7       k * lane stride
        0x03, 0x0e, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00, // 34 add  r14, r14, r15      r14 = offset
        0x0d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // 35 jmp  39                 store
        0x06, 0x0f, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, // 36 and  r15, r13, r10      k & 2
        0x0e, 0x00, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x00, // 37 brz  r15, 39            lanes 0,1 sit at the column base
        0x03, 0x0e, 0x0e, 0x08, 0x00, 0x00, 0x00, 0x00, // 38 add  r14, r14, r8       + pair stride
        0x0c, 0x00, 0x03, 0x0e, 0x00, 0x00, 0x00, 0x00, // 39 st   Mem[r3], r14       Mem[4*(dir*144+round*16+i)] = off
        0x03, 0x03, 0x03, 0x0c, 0x00, 0x00, 0x00, 0x00, // 40 add  r3, r3, r12        next word
        0x04, 0x0d, 0x0c, 0x09, 0x00, 0x00, 0x00, 0x00, // 41 sub  r13, r12, r9       1
        0x03, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, // 42 add  r0, r0, r13        i++
        0x08, 0x0d, 0x0c, 0x0a, 0x00, 0x00, 0x00, 0x00, // 43 shl  r13, r12, r10      16
        0x04, 0x0d, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, // 44 sub  r13, r0, r13       i - 16
        0x0e, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, // 45 brz  r13, 47            all 16 bytes done
        0x0d, 0x00, 0x00, 0x00, 0xee, 0xff, 0xff, 0xff, // 46 jmp  28                 next state byte
        0x04, 0x0d, 0x0c, 0x09, 0x00, 0x00, 0x00, 0x00, // 47 sub  r13, r12, r9       1
        0x03, 0x01, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, // 48 add  r1, r1, r13        round++
        0x08, 0x0d, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00, // 49 shl  r13, r9, r10       12
        0x04, 0x0d, 0x0d, 0x09, 0x00, 0x00, 0x00, 0x00, // 50 sub  r13, r13, r9       9
        0x04, 0x0d, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, // 51 sub  r13, r1, r13       round - 9
        0x0e, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, // 52 brz  r13, 54            nine rounds done
        0x0d, 0x00, 0x00, 0x00, 0xd3, 0xff, 0xff, 0xff, // 53 jmp  8                  next round
        0x04, 0x0d, 0x0c, 0x09, 0x00, 0x00, 0x00, 0x00, // 54 sub  r13, r12, r9       1
        0x03, 0x02, 0x02, 0x0d, 0x00, 0x00, 0x00, 0x00, // 55 add  r2, r2, r13        dir++
        0x04, 0x0d, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, // 56 sub  r13, r2, r10       dir - 2
        0x0e, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, // 57 brz  r13, 59            both directions done
        0x0d, 0x00, 0x00, 0x00, 0xcd, 0xff, 0xff, 0xff, // 58 jmp  7                  next direction
        0x02, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // 59 mov  r0, r11            success: the plan is in VM memory
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 60 halt                    return r0 = 0
};

// The VM's memory plane. The pass uses this array instead of a private alloca
// because it is defined here (see HSVMLowering.cpp): St writes land in it and the
// host reads them back after the call, which is how 288 offsets leave the VM
// without a new opcode. It is cleared at the start of every call, so a caller
// reads it before calling again.
//
// Tld's view of host memory: the unmasked schedule block (Tld refuses a null
// pointer, a misaligned offset or a word that runs past the end).
extern "C" {
void *hsvm_table = nullptr;
unsigned long long hsvm_table_len = 0;
unsigned char hsvm_mem[HY_VM_MEM] __attribute__((aligned(16)));
}

void hy_vm_set_table(const void *tab, uint64_t len) {
    hsvm_table = const_cast<void *>(tab);
    hsvm_table_len = len;
}

// Word k of the plan, little-endian, as the VM left it.
static uint32_t hy_vm_word(uint32_t idx) {
    const unsigned char *p = hsvm_mem + 4u * idx;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int hy_vm_plan(uint32_t off[2][HY_VM_ROUNDS][16]) {
    const int32_t r = hsvm_entry(0); // one call, whole plan
    if (r < 0) {                     // 0xFFFFFFFE fault / 0xFFFFFFFF pc out of range
        for (int d = 0; d < 2; d++)
            for (int q = 0; q < HY_VM_ROUNDS; q++)
                for (int i = 0; i < 16; i++) off[d][q][i] = 0;
        return -1;
    }
    for (int d = 0; d < 2; d++)
        for (int q = 0; q < HY_VM_ROUNDS; q++)
            for (int i = 0; i < 16; i++)
                off[d][q][i] = hy_vm_word((uint32_t)((d * HY_VM_ROUNDS + q) * 16 + i));
    return 0;
}

int hy_vm_offsets(int32_t dir, int32_t round, uint32_t off[16]) {
    for (int i = 0; i < 16; i++) off[i] = 0;
    if (dir < 0 || dir > 1 || round < 0 || round >= HY_VM_ROUNDS) return -1;
    uint32_t plan[2][HY_VM_ROUNDS][16];
    if (hy_vm_plan(plan) != 0) return -1;
    for (int i = 0; i < 16; i++) off[i] = plan[dir][round][i];
    return 0;
}
