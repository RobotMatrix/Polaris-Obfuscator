// 烘焙数据面：全部轮次都在表里。运行时没有 S 盒，也没有轮密钥异或。
#ifdef WBAES_DFA_SELFTEST
// Test-only hook: corrupt the first traversal's state once, to prove the second
// traversal and the comparison catch a single-byte fault. Not compiled into the
// shipped binary.
static int g_dfa_once = 1;
#endif

// One traversal of the table network, factored out so the encryption path can run
// it twice over independent buffers.
static void hy_encrypt_once(const uint8_t in[16], uint8_t out[16], uint32_t env,
                            int arm_fault) {
    uint8_t s[16], n[16];
    for (int i = 0; i < 16; i++) s[i] = in[i];
    for (int r = 0; r < HY_MC_ROUNDS; r++) {
        hy_mc_round(kHyTab, hy_enc_col(r, 0), r, 0, 1, s, n, env);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    if (arm_fault) {
#ifdef WBAES_DFA_SELFTEST
        if (g_dfa_once) {
            g_dfa_once = 0;
            s[7] ^= 0x40u; // the shape of a DFA fault: one state byte
        }
#else
        (void)arm_fault;
#endif
    }
    hy_pair_map(kHyTab, hy_enc_final(), s, out, env, 0, 9, 1);
}

// DFA defense: the whole network runs twice over independent buffers and the two
// ciphertexts must agree. A single injected fault lands in one traversal, the
// comparison fails, and the caller gets garbage instead of a faulty ciphertext -
// which is what a differential attack needs. Cost: 2x table traffic.
static void hy_encrypt(const uint8_t in[16], uint8_t out[16]) {
    uint32_t env = g_env ^ g_poison;
    uint8_t ct1[16], ct2[16];
    hy_encrypt_once(in, ct1, env, 1);
    hy_encrypt_once(in, ct2, env, 0);
    if (memcmp(ct1, ct2, 16) != 0) {
        wbaes_key::g_key_tampered |= 0x8000u; // detected: never emit either one
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_runtime_rand() & 0xFF);
        return;
    }
    for (int i = 0; i < 16; i++) out[i] = ct1[i];
}

static void hy_decrypt_once(const uint8_t in[16], uint8_t out[16], uint32_t env) {
    uint8_t s[16], t[16], n[16];
    hy_pair_map(kHyTab, hy_dec_entry(), in, s, env, 1, 0, 2);
    for (int step = 0; step < HY_DEC_STEPS; step++) {
        hy_mc_round(kHyTab, hy_dec_mc(step), step, 1, 0, s, t, env);
        hy_pair_map(kHyTab, hy_dec_sb(step), t, n, env, 1, 20 + step, 2);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_pair_map(kHyTab, hy_dec_tail(), s, out, env, 1, 40, 0);
}

// Same DFA defense as the encryption path: decryption faults leak the round keys
// just as well, so the network runs twice and both results must agree.
static void hy_decrypt(const uint8_t in[16], uint8_t out[16]) {
    uint32_t env = g_env ^ g_poison;
    uint8_t pt1[16], pt2[16];
    hy_decrypt_once(in, pt1, env);
    hy_decrypt_once(in, pt2, env);
    if (memcmp(pt1, pt2, 16) != 0) {
        wbaes_key::g_key_tampered |= 0x8000u;
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_runtime_rand() & 0xFF);
        return;
    }
    for (int i = 0; i < 16; i++) out[i] = pt1[i];
}

static void hy_protect(const uint8_t in[16], uint8_t out[16], int dec) {
    if (dec) hy_decrypt(in, out);
    else hy_encrypt(in, out);
}
