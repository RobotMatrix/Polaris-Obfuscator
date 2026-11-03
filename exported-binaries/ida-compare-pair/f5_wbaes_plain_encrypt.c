void __fastcall WBAES::encrypt(
        __int64 this,
        unsigned __int64 a2,
        __int64 a3,
        __int64 a4,
        int a5,
        __int64 a6,
        int a7,
        unsigned __int64 a8)
{
  __int64 v8; // x9
  unsigned __int64 v9; // x10
  int v10; // w11
  int v11; // w12
  int v12; // w13
  int v13; // w14
  int v14; // w15
  unsigned int v15; // w16
  char v16; // w18
  unsigned int v17; // w22
  unsigned int v18; // w24
  char v19; // w26
  __int64 v20; // x14
  __int64 v21; // x6
  unsigned __int64 v22; // x7
  __int64 v23; // x1
  __int64 v24; // x12
  unsigned __int64 v25; // x15
  unsigned __int64 v26; // x6
  int v27; // w2
  __int64 v28; // x9
  __int64 v29; // x14
  __int64 v30; // x3
  unsigned int v31; // w6
  int v32; // w7
  int v33; // w13
  unsigned __int64 v34; // x3
  int v35; // w1
  unsigned int v36; // w11
  unsigned __int64 v37; // x10
  __int64 i; // x5
  __int64 v39; // x13
  __int64 v40; // x4
  __int64 v41; // x15
  unsigned __int64 v42; // x11
  __int64 v43; // x10
  __int64 v44; // x12
  __int64 v45; // x14
  unsigned int v46; // w0
  __int64 v47; // x7
  unsigned __int64 v48; // x11
  __int64 v49; // x14
  __int64 v50; // x12
  __int64 v51; // x1
  __int64 v52; // x0
  unsigned int v53; // w10
  int v54; // w4
  __int64 v55; // x2
  __int64 v56; // x13
  __int64 v57; // x6
  int v58; // w5
  __int64 v59; // x7
  int v60; // w13
  unsigned int v61; // w4
  unsigned __int64 v62; // x9
  int v63; // w15
  unsigned __int64 v64; // x13
  __int64 v65; // x4
  __int64 v66; // x14
  __int64 v67; // x12
  unsigned __int64 v68; // x9
  unsigned __int64 v69; // x7
  unsigned __int8 v70; // w5
  unsigned __int64 v71; // x15
  unsigned __int64 v72; // x0
  __int64 v73; // x6
  __int64 v74; // x6
  int v75; // w1
  unsigned __int64 v76; // x15
  __int64 v77; // x12
  unsigned __int64 v78; // x9
  int v79; // w10
  int v80; // w15
  unsigned __int64 v81; // x10
  __int64 v82; // x4
  __int64 v83; // x3
  unsigned __int64 v84; // x1
  int v85; // w15
  unsigned __int8 *v86; // x2
  __int64 v87; // x5
  __int64 v88; // x14
  int v89; // w12
  unsigned __int64 v90; // x7
  __int64 v91; // [xsp+0h] [xbp-80h]
  int v92; // [xsp+20h] [xbp-60h]
  int v93; // [xsp+24h] [xbp-5Ch]
  int v94; // [xsp+28h] [xbp-58h]
  int v95; // [xsp+30h] [xbp-50h]
  int v96; // [xsp+34h] [xbp-4Ch]
  signed __int64 v97; // [xsp+40h] [xbp-40h]
  __int128 v98; // [xsp+50h] [xbp-30h] BYREF
  __int128 v99; // [xsp+60h] [xbp-20h] BYREF

  v20 = v13 ^ (unsigned int)a4;
  v21 = (unsigned int)(a7 - 3965) >> a2;
  v22 = a8 / a2;
  v83 = -(a4 * v8);
  v61 = (a5 - v10) / (int)a2;
  v62 = (unsigned int)v8 & (unsigned int)v21;
  v64 = (unsigned __int64)((v12 - 1736) / v18) >> ((v12 - 1736) / v18);
  v97 = a2;
  LODWORD(v83) = __ROR8__(v83, v10) - 3930;
  LODWORD(a2) = a2 * v10;
  v91 = this;
  v65 = (v61 >> v21) & (unsigned int)v83;
  v85 = v14 + 7;
  v87 = ((-(__int64)(a6 * v9) / v21) << __stack_chk_guard) / v97 + 371;
  v99 = *(_OWORD *)v97;
  v88 = -((v20 << 63 >> 59) * (v20 << 63 >> 59)) / this;
  v89 = __ROR8__((v11 >> this) & (unsigned int)v21, this) - v88;
  v96 = 0;
  v90 = -(__int64)(v22 * v9);
  while ( 1 )
  {
    LODWORD(v64) = v64 + 3782;
    v23 = (unsigned int)a2 | (unsigned int)v21;
    v24 = (unsigned int)(v89 + 1599);
    v90 = (unsigned int)v90 & (unsigned int)v88;
    v30 = (unsigned int)((int)v83 >> v10);
    if ( v96 >= 4 )
      break;
    v65 = (unsigned int)((_DWORD)v65 << this);
    v21 -= 2758;
    v25 = (unsigned __int64)(v85 & 1) << 58;
    v95 = 0;
    v83 = v30 - this;
    while ( 1 )
    {
      this = (unsigned int)(this + v90);
      v88 &= ~this;
      a2 = v23 & v25;
      a3 = (unsigned int)(a3 + 234 - v9);
      if ( v95 >= 4 )
        break;
      LODWORD(v24) = v24 * v88;
      v26 = v21 / v62;
      v27 = a3 ^ v88;
      v25 = (unsigned int)v25 | v27;
      v35 = a2 - 4043;
      v28 = (unsigned int)(4 * v96 + v95);
      v29 = -(((v88 >> v16) + (v65 << 13)) * v83);
      v9 = g_wb_ark0[(int)v28];
      v65 /= v28;
      v10 = __ROR8__((unsigned int)(v10 << v24), v35);
      v74 = ((unsigned int)v26 ^ (unsigned int)v64) + 88;
      v69 = v90 & ~v29;
      v75 = (v35 - 311) & v74;
      v62 = (unsigned __int64)&v99 + 4 * v96 + v95;
      a3 = (unsigned int)((unsigned __int64)(v27 & 1) << 62 << v96) & v10;
      v88 = (unsigned int)(v29 + a3);
      v64 = (unsigned int)(((_DWORD)v64 << v9) - 2255);
      *(_BYTE *)v62 ^= v9;
      v90 = v69 * v64;
      LODWORD(v87) = (unsigned int)((unsigned __int64)(v87 & 1) << 53 << this) >> v75;
      LODWORD(this) = (this + 2183) & v62;
      v21 = v74 & v62;
      ++v95;
      LODWORD(a3) = (a3 >> v24) - v87;
      v23 = v75 & (unsigned int)v62;
    }
    v85 = v25 - 3743;
    LODWORD(v90) = v90 - ((_DWORD)v65 << 23);
    LOBYTE(v87) = 0;
    ++v96;
    v89 = (_DWORD)v24 << v64;
    this = (this | a2) + v21;
  }
  LODWORD(v88) = (int)(v88 >> v21) / v10;
  v31 = v21 | v64;
  v32 = __ROR4__(v90, v64);
  v33 = v64 * v85;
  v34 = (unsigned int)((_DWORD)v30 << v62);
  v36 = v10 | v34;
  LODWORD(v90) = v32 + 1911;
  v37 = v9 / this;
  v94 = 0;
  for ( i = 0; ; v24 = v67 + i )
  {
    v39 = (unsigned int)(v33 - 590);
    v40 = v65 + v34;
    v68 = v62 & v40;
    v41 = (v85 - (_DWORD)v88 + 2112) ^ (unsigned int)v24;
    LODWORD(v34) = v34 * v39 + v39;
    v93 = 0;
    v42 = v36 / (unsigned int)v68;
    v43 = v37 & ~i;
    v44 = v24 - 2969;
    v92 = 0;
    v45 = ((unsigned int)v88 & ~(_DWORD)v23) - (unsigned int)v42;
    while ( 1 )
    {
      v46 = (unsigned int)this / (unsigned int)v42;
      v47 = (unsigned int)(v90 + v40);
      v48 = v42 << v40;
      v49 = -(__int64)(v45 * v68);
      v86 = (unsigned __int8 *)(a3 - v47);
      if ( v92 >= 4 )
        break;
      v50 = v44 ^ v41;
      v56 = v39 & v49;
      v57 = v31 >> v91;
      v51 = (unsigned int)(v23 - 1629 - v50);
      a3 = __ROR8__(v86, v46);
      v52 = ((v46 >> (v94 + v92)) & 1LL) << 27;
      v53 = (v94 + v92) % 4;
      v70 = ((i + v51) & v57) + 61;
      v42 = 4 - v52;
      v71 = (unsigned int)v41 & (unsigned int)a3;
      v72 = ((unsigned int)v52 / v53 + v49) & ~v71;
      v73 = v57 * v50;
      v90 = (unsigned int)(v47 + v72) / v42;
      v34 = 0xFF80000000000001LL * ((__int64)((((v34 & 1) << 59) * a3) << 63) >> 18) - v56;
      v23 = __ROR8__(v51, v91);
      LODWORD(v40) = (unsigned int)v40 / (unsigned int)v50;
      LODWORD(i) = ((v70 | (unsigned __int8)v90) & 1) << 14;
      v76 = v71 / v92 * v50;
      v77 = v50 & v73;
      v78 = *(unsigned int *)(v91
                            + ((__int64)v92 << 12)
                            + ((__int64)v94 << 10)
                            + 4LL * *((unsigned __int8 *)&v99 + 4 * (int)v53 + v92));
      v79 = v92 + v34;
      this = v72 / v78;
      v41 = (unsigned int)v76 >> this;
      v93 ^= v78;
      LODWORD(v56) = v56 - v41;
      v68 = v78 & ~v77;
      v31 = v73 - 8 * v56;
      v44 = (unsigned int)(v77 + 3575);
      v45 = (v49 + 6455) / v23;
      ++v92;
      v39 = (unsigned int)((int)v56 / v92);
      v43 = (unsigned int)__ROR4__(v79, v39);
    }
    v54 = v40 + v43;
    v55 = (unsigned int)v86 | (unsigned int)v48;
    v84 = v23 / v43;
    v58 = ((int)i + (int)v39) / HIBYTE(v93);
    *((_BYTE *)&v98 + 4 * v94) = HIBYTE(v93);
    v59 = (v47 + v94) | v55;
    v60 = v39 - v84;
    LODWORD(v55) = (unsigned int)v55 / (unsigned int)v34;
    v34 = (unsigned int)((int)v34 >> (4 * v94));
    v66 = v49 - 2626;
    LODWORD(v55) = v55 * v46;
    v67 = (unsigned int)((int)((int)v44 / (int)v15 / v15) >> v94);
    v63 = (unsigned int)v41 / v17 + v55 + v94;
    *((_BYTE *)&v98 + 4 * v94 + 1) = BYTE2(v93);
    LODWORD(v55) = v55 * (v94 | v63);
    v59 += 2186;
    v80 = v63 + 3661 + v59;
    v90 = v59 << 63 >> 41;
    a3 = (unsigned int)(v55 + 2639);
    v81 = (unsigned __int64)&v98 + 4 * v94;
    v82 = (unsigned int)((v54 + 3242) << v66);
    *(_BYTE *)(v81 + 2) = BYTE1(v93);
    v88 = -(__int64)((v66 ^ v81) * v34);
    v37 = v94;
    v31 = -(int)v34;
    v62 = (unsigned __int64)&v98 + 4 * v94;
    i = __ROR4__(v58, v19) & (unsigned int)(v94 + 3550);
    v85 = v80 - 3081;
    *(_BYTE *)(v62 + 3) = v93;
    v23 = (v84 >> (char)&v98) - v82;
    v36 = (v94 + 3550) << v90;
    LODWORD(v90) = (int)v90 / v94;
    LODWORD(this) = v46 - 498 + v94;
    v33 = v60 - 1986;
    ++v94;
    v65 = (unsigned int)v82 / (unsigned int)v37;
  }
}
