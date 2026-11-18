// wbaes_vm.h — host side of the HSV virtual machine used by the baked path.
//
// The VM program (ISA v2, Tld) computes, for every state byte of every round and
// both directions, the table offset the reader must use:
//
//   off(dir, round, i) = base[dir] + round * round_stride[dir]
//                      + (i >> 2) * col_stride + lane_stride(fam, i & 3)
//
// The schedule block is read with Tld from host memory (@hsvm_table points at
// it), so the offsets follow the table's own schedule bytes instead of constants
// baked into the C++ reader.
//
// One call is enough for the whole plan: the program walks 2 directions x 9
// rounds x 16 state bytes and stores all 288 offsets into VM memory with St. The
// pass publishes that memory as @hsvm_mem (see wbaes_vm.cpp), so the host reads
// the words out after the call instead of asking for one offset at a time.
//
// wbaes_vm.cpp is the only translation unit compiled with -mllvm -passes=hsvm;
// that pass replaces the body of hsvm_entry with the lowered program. There is
// no interpreter and no opcode dispatch loop in the shipped code.
#pragma once
#include <cstdint>

// Rounds per direction in the plan (AES-128 white-box: 9 table rounds).
static const int HY_VM_ROUNDS = 9;
// Bytes of VM memory the pass hands to this translation unit.
static const int HY_VM_MEM = 4096;

extern "C" {
// Lowered from @hsvm_bytecode by -passes=hsvm. One call computes the complete
// offset plan and leaves it in hsvm_mem at 4 * ((dir * 9 + round) * 16 + i).
// Returns 0, or a negative value on a VM fault.
int32_t hsvm_entry(int32_t arg);
// The VM's 4 KiB memory plane. Defining this array is what makes the pass use it
// instead of a private alloca, so it is the channel the offsets leave through.
extern unsigned char hsvm_mem[HY_VM_MEM];
// Point Tld at the (unmasked) schedule block; called once, after unmasking.
void hy_vm_set_table(const void *tab, uint64_t len);
// One VM call: fills off[dir][round][i] with all 288 offsets. Returns 0 on
// success, -1 if the VM faulted (bad table pointer, out-of-range or misaligned
// read). Range checking against the table length is the caller's business.
int hy_vm_plan(uint32_t off[2][HY_VM_ROUNDS][16]);
// The same plan, one (dir, round) slice at a time. Runs the program and reads the
// sixteen words back; kept for tests and for callers that want a single round.
int hy_vm_offsets(int32_t dir, int32_t round, uint32_t off[16]);
}
