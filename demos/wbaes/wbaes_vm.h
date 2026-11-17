// wbaes_vm.h — host side of the HSV virtual machine used by the baked path.
//
// The VM program (ISA v2, Tld) computes, for each state byte, the table offset
// of this round: base + column offset + family-dependent lane stride. The
// schedule block is read with Tld from host memory (@hsvm_table points at it),
// so the offsets follow the table's own schedule bytes instead of constants
// baked into the C++ reader.
//
// wbaes_vm.cpp is the only translation unit compiled with -mllvm -passes=hsvm;
// that pass replaces the body of hsvm_entry with the lowered program. There is
// no interpreter and no opcode dispatch loop in the shipped code.
#pragma once
#include <cstdint>

extern "C" {
// Lowered from @hsvm_bytecode by -passes=hsvm. arg = (dir << 8) | (round << 4) | i
// with dir 0 = encrypt, 1 = decrypt, round 0..8, i = state byte 0..15.
// Returns the table offset in bytes, or a negative value on a VM fault.
int32_t hsvm_entry(int32_t arg);
// Point Tld at the (unmasked) schedule block; called once, after unmasking.
void hy_vm_set_table(const void *tab, uint64_t len);
// Sixteen calls to hsvm_entry, one per state byte. Returns 0 on success, -1 if
// the VM faulted (bad table pointer, out-of-range or misaligned read).
int hy_vm_offsets(int32_t dir, int32_t round, uint32_t off[16]);
}
