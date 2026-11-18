// test_vm_offsets.cpp — the HSV offset program against a C reference.
//
// Feeds synthetic schedule blocks to the lowered VM (linked from wbaes_vm.cpp)
// and compares every (dir, round, state byte) offset with the formula the
// program is supposed to implement. Two of the blocks use layout numbers that
// are not the shipped ones: if any constant were baked into the bytecode
// instead of read through Tld, those cases would disagree.
//
// Both ways of asking for the offsets are checked: one call for the whole 288
// entry plan (hy_vm_plan, the path the runtime uses) and one (dir, round) slice
// at a time (hy_vm_offsets). They must agree with the reference and each other.
//
//   test_vm_offsets      exit 0 = PASS
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "wbaes_vm.h"

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t expect(const uint8_t *blk, int dir, int round, int i) {
    const uint32_t base = rd32(blk + 32 + 4 * dir);
    const uint32_t stride = rd32(blk + 40 + 4 * dir);
    const uint32_t col_stride = rd32(blk + 48);
    const uint32_t lane = rd32(blk + 52);
    const uint32_t pair = rd32(blk + 56);
    const uint8_t fam = blk[dir * 16 + round];
    const int k = i & 3, col = i >> 2;
    const uint32_t st = (fam == 0) ? ((k >= 2) ? pair : 0u) : (uint32_t)k * lane;
    return base + (uint32_t)round * stride + (uint32_t)col * col_stride + st;
}

static int check_block(const char *what, uint8_t blk[64]) {
    hy_vm_set_table(blk, 64);
    int bad = 0;
    for (int dir = 0; dir < 2; dir++) {
        for (int round = 0; round < 9; round++) {
            uint32_t off[16];
            if (hy_vm_offsets(dir, round, off) != 0) {
                printf("%s dir=%d round=%d: VM faulted\n", what, dir, round);
                return 1;
            }
            for (int i = 0; i < 16; i++) {
                const uint32_t want = expect(blk, dir, round, i);
                if (off[i] != want) {
                    if (bad++ < 4)
                        printf("%s dir=%d round=%d i=%d: got 0x%08x want 0x%08x\n", what,
                               dir, round, i, off[i], want);
                }
            }
        }
    }
    printf("%-22s %s\n", what, bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}

// The batch form: one call must hand over all 288 offsets, for both directions,
// exactly where the slice-by-slice form reads them.
static int check_plan(const char *what, uint8_t blk[64]) {
    hy_vm_set_table(blk, 64);
    static uint32_t plan[2][HY_VM_ROUNDS][16];
    if (hy_vm_plan(plan) != 0) {
        printf("%-22s FAIL (VM faulted)\n", what);
        return 1;
    }
    int bad = 0;
    for (int dir = 0; dir < 2; dir++)
        for (int round = 0; round < HY_VM_ROUNDS; round++)
            for (int i = 0; i < 16; i++) {
                const uint32_t want = expect(blk, dir, round, i);
                if (plan[dir][round][i] != want) {
                    if (bad++ < 4)
                        printf("%s dir=%d round=%d i=%d: got 0x%08x want 0x%08x\n", what,
                               dir, round, i, plan[dir][round][i], want);
                }
            }
    printf("%-22s %s (288 offsets, one call)\n", what, bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}

int main(void) {
    int fail = 0;
    uint8_t blk[64];

    // The shipped layout, and the shipped schedule: every (dir, round) is F4, so
    // every lane takes its table from `k * lane_stride` with lane_stride =
    // HY_W16_TAB (131072 B = one 2^16-entry pair table).
    static const uint8_t enc[9] = {4, 4, 4, 4, 4, 4, 4, 4, 4};
    static const uint8_t dec[9] = {4, 4, 4, 4, 4, 4, 4, 4, 4};
    memset(blk, 0, sizeof blk);
    memcpy(blk, enc, 9);
    memcpy(blk + 16, dec, 9);
    wr32(blk + 32, 0u);
    wr32(blk + 36, 30408704u);
    wr32(blk + 40, 3145728u);
    wr32(blk + 44, 4194304u);
    wr32(blk + 48, 786432u);
    wr32(blk + 52, 131072u);
    wr32(blk + 56, 262144u);
    fail |= check_block("shipped-layout F4", blk);
    fail |= check_plan("plan: shipped F4", blk);

    // The VM still has both lane addressing classes: family 0 (lanes 2,3 one pair
    // table further) and every nonzero family (one table per lane). Only the
    // nonzero class is reachable from a build now, but the branch is part of the
    // bytecode and a damaged family byte would take it, so both are checked.
    for (int fam = 0; fam < 5; fam++) {
        if (fam == 4) continue; // == the shipped block above
        uint8_t b2[64];
        memcpy(b2, blk, sizeof b2);
        memset(b2, fam, 9);
        memset(b2 + 16, fam, 9);
        char name[32];
        snprintf(name, sizeof name, "shipped-layout F%d", fam);
        fail |= check_block(name, b2);
    }

    // Layout numbers that are not the shipped ones: they can only be right if
    // the program really reads them from the table.
    memset(blk, 0, sizeof blk);
    wr32(blk + 32, 1000u);
    wr32(blk + 36, 7000000u);
    wr32(blk + 40, 4096u);
    wr32(blk + 44, 65536u);
    wr32(blk + 48, 12288u);
    wr32(blk + 52, 256u);
    wr32(blk + 56, 4096u);
    for (int round = 0; round < 9; round++) {
        blk[round] = (uint8_t)(round & 3);
        blk[16 + round] = (uint8_t)((round + 1) & 3);
    }
    fail |= check_block("foreign-layout mixed", blk);
    fail |= check_plan("plan: foreign mixed", blk);

    // A table shorter than the words the program reads must fault, not read on.
    hy_vm_set_table(blk, 40);
    uint32_t off[16];
    const int faulted = hy_vm_offsets(0, 0, off) != 0;
    printf("%-22s %s\n", "short table", faulted ? "PASS" : "FAIL");
    fail |= faulted ? 0 : 1;

    // A null table must fault too.
    hy_vm_set_table(nullptr, 64);
    const int nulled = hy_vm_offsets(0, 0, off) != 0;
    printf("%-22s %s\n", "null table", nulled ? "PASS" : "FAIL");
    fail |= nulled ? 0 : 1;

    printf("vm-offsets: %s\n", fail ? "FAIL" : "PASS");
    return fail;
}
