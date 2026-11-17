// 烘焙数据面：全部轮次都在表里。运行时没有 S 盒，也没有轮密钥异或。
static void hy_encrypt(const uint8_t in[16], uint8_t out[16]) {
    uint32_t env = g_env ^ g_poison;
    uint8_t s[16], n[16];
    for (int i = 0; i < 16; i++) s[i] = in[i];
    for (int r = 0; r < HY_MC_ROUNDS; r++) {
        hy_mc_round(kHyTab, hy_enc_col(r, 0), r, 0, 1, s, n, env);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_pair_map(kHyTab, hy_enc_final(), s, out, env, 0, 9, 1);
}

static void hy_decrypt(const uint8_t in[16], uint8_t out[16]) {
    uint32_t env = g_env ^ g_poison;
    uint8_t s[16], t[16], n[16];
    hy_pair_map(kHyTab, hy_dec_entry(), in, s, env, 1, 0, 2);
    for (int step = 0; step < HY_DEC_STEPS; step++) {
        hy_mc_round(kHyTab, hy_dec_mc(step), step, 1, 0, s, t, env);
        hy_pair_map(kHyTab, hy_dec_sb(step), t, n, env, 1, 20 + step, 2);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_pair_map(kHyTab, hy_dec_tail(), s, out, env, 1, 40, 0);
}

static void hy_protect(const uint8_t in[16], uint8_t out[16], int dec) {
    if (dec) hy_decrypt(in, out);
    else hy_encrypt(in, out);
}
