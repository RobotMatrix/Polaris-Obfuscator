// vm_negative_test.cpp — is the HSV bytecode still driving the table addresses
// after the sections and symbols were renamed?
//
// V2 of VM-REQUIREMENT.md: damage one byte of the schedule block that the reader
// never looks at directly (byte 48, the low byte of the column stride the VM
// multiplies by), after the one-time unmask has run. The schedule checksum covers
// only the family bytes and the sampled seal looks at every 4096th byte, so the
// only thing that can notice is the reader using the VM's offsets:
//
//   intact   -> ciphertext A
//   damaged  -> ciphertext B != A   (the VM recomputed the plan from the damaged
//                                    schedule block, so every lane address moved)
//   restored -> ciphertext A again
//
// If the VM were not running - if the addresses came from constants - all three
// would be equal.
//
// Build with -DWBAES_VM_SCHEDTEST so the one-byte hook exists:
//   clang++ ... -DWBAES_VM_SCHEDTEST vm_negative_test.cpp hy_tab.S wbaes_vm.o
#define WBAES_NO_MAIN
#include "demo_wbaes.cpp"

int main() {
    WBAES wb;
    wb.init();
    uint8_t pt[16], a[16], b[16], c[16];
    wbaes_key::hy_kat_plaintext(pt);
    wb.encrypt(pt, a);
    hy_test_flip_sched();
    wb.encrypt(pt, b);
    hy_test_flip_sched();
    wb.encrypt(pt, c);
    const bool intact_ok = memcmp(a, b, 16) != 0;
    const bool restored_ok = memcmp(a, c, 16) == 0;
    printf("intact  : ");
    for (int i = 0; i < 16; i++) printf("%02x", a[i]);
    printf("\ndamaged : ");
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    printf("\nrestored: ");
    for (int i = 0; i < 16; i++) printf("%02x", c[i]);
    printf("\nvm-negative: %s\n", (intact_ok && restored_ok) ? "PASS (the VM drives the addresses)"
                                                            : "FAIL");
    return (intact_ok && restored_ok) ? 0 : 1;
}
