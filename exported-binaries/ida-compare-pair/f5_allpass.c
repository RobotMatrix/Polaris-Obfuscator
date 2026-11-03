__int64 __fastcall shortestPath(unsigned int (*a1)[9], int a2)
{
  char v2; // w19
  __int64 v3; // x21
  __int64 v4; // x24
  char v5; // w26
  int v6; // w15
  char v7; // w0
  __int64 v8; // x4
  __int64 v9; // x5
  __int64 v10; // x6
  __int64 v11; // x7
  int v12; // w9
  int v13; // w11
  __int64 v14; // x13
  __int64 v15; // x14
  int v16; // w15
  __int64 v17; // x16
  __int64 v18; // x2
  __int64 v19; // x2
  __int64 v20; // x12
  __int64 v21; // x12
  int v22; // w3
  int v23; // w3
  unsigned int v24; // w0
  __int64 v25; // x3
  int v26; // w1
  unsigned __int64 v27; // x2
  int v28; // w9
  __int64 v29; // x1
  __int64 v30; // x14
  __int64 v31; // x7
  __int64 v32; // x5
  __int64 v33; // x5
  __int64 v34; // x3
  __int64 v35; // x1
  __int64 v36; // x10
  unsigned __int64 v37; // x4
  __int64 v38; // x0
  __int64 v39; // x0
  int v40; // w15
  unsigned int v41; // w8
  int v42; // w13
  int v43; // w12
  unsigned __int64 v44; // x1
  int v45; // w11
  __int64 v46; // x2
  int v47; // w12
  __int64 v48; // x3
  __int64 v49; // x3
  __int64 v50; // x13
  __int64 v51; // x7
  __int64 v52; // x11
  __int64 v53; // x0
  int v54; // w12
  __int64 v55; // x4
  __int64 v56; // x15
  __int64 v57; // x15
  __int64 v58; // x7
  __int64 v59; // x15
  __int64 v60; // x12
  signed __int64 v61; // x2
  unsigned __int64 v62; // x10
  __int64 v63; // x15
  int i; // w13
  unsigned __int64 v65; // x13
  __int64 v66; // x7
  __int64 v67; // x5
  __int64 v68; // x6
  __int64 v69; // x9
  unsigned __int64 v70; // x4
  unsigned __int64 v71; // x15
  unsigned __int64 v72; // x4
  unsigned __int64 v73; // x5
  unsigned __int64 v74; // x0
  char *v75; // x10
  int v76; // w2
  __int64 v77; // x8
  char v78; // w13
  __int64 v79; // x1
  int v80; // w2
  __int64 v81; // x0
  __int64 v82; // x5
  int v83; // w15
  char v84; // w6
  __int64 v85; // x0
  __int64 v86; // x1
  int v88; // w5
  __int64 v89; // x7
  int v92; // [xsp+28h] [xbp-68h]
  int v93; // [xsp+2Ch] [xbp-64h]
  int v94; // [xsp+30h] [xbp-60h]
  unsigned int v95; // [xsp+34h] [xbp-5Ch]
  int v96; // [xsp+38h] [xbp-58h]
  int v97; // [xsp+3Ch] [xbp-54h]
  int v98; // [xsp+40h] [xbp-50h]
  _BYTE v99[14]; // [xsp+54h] [xbp-3Ch] BYREF
  _DWORD v100[9]; // [xsp+64h] [xbp-2Ch] BYREF
  __int64 v101; // [xsp+88h] [xbp-8h]

  *(_DWORD *)v99 = 903831252;
  *(_DWORD *)&v99[3] = -701463499;
  v7 = sub_1000020A0();
  v19 = v18 << v7;
  v21 = -(v20 * v15);
  v23 = v22 + v10;
  v24 = (unsigned int)a1 ^ v23;
  v25 = (unsigned int)__ROR4__(v23, v23);
  v26 = a2 + v21;
  v98 = 0;
  v27 = __ROR8__(v19, v17);
  while ( 1 )
  {
    v28 = v12 + 1380;
    v29 = (unsigned int)(v26 / v28);
    v30 = v15 ^ v27;
    v81 = v24 & v28;
    if ( v98 >= 9 )
      break;
    v82 = __ROR8__(v9, v17);
    v26 = v29 + 1350;
    v31 = (unsigned int)(((int)v11 - (int)v81) / (int)v82);
    v33 = v82 ^ v25;
    v47 = __ROR4__(v21, v21);
    v34 = v25 - 3996;
    v100[v98] = 1061109567;
    v10 &= v34;
    v12 = v98;
    v49 = (v34 & v31) - (v14 << 19);
    v15 = ((unsigned int)v30 | (unsigned int)v81) - v26;
    v24 = v81 / v17 - 2145;
    v14 = (unsigned int)(v14 + 816);
    v99[v98 + 7] = 0;
    v25 = v49 - v33;
    v6 = __ROR8__((unsigned int)(v16 + v47), v33);
    LODWORD(v21) = v47 ^ v31;
    v16 = v6 + 2712;
    v9 = (unsigned int)v33 | (unsigned int)v10;
    ++v98;
    v11 = ((int)((_DWORD)v31 << 31) >> 30) | (unsigned int)v21;
  }
  LODWORD(v36) = a2;
  v37 = v8 & ~v10;
  v39 = (unsigned int)((_DWORD)v81 << (v98 >= 9));
  v89 = (unsigned int)__ROR8__(v11, v21) << v39;
  v100[a2] = 0;
  v40 = (v16 - (int)v29) / a2;
  LODWORD(v9) = v9 & v10;
  v97 = 0;
  v42 = v14 - 2054;
  while ( 1 )
  {
    v43 = v21 + 1302;
    v44 = v29 - 823;
    v45 = v13 ^ v39;
    v46 = (unsigned int)v27 / (v97 - 8);
    v48 = (unsigned int)v25 >> v43;
    v50 = (unsigned int)(v42 + 3867);
    if ( v97 >= 8 )
      break;
    v51 = v89 + (v48 << 29);
    v52 = (unsigned int)(v45 + v46);
    LODWORD(v21) = v43 ^ v40;
    v25 = v48 * v50;
    v32 = (unsigned int)__ROR4__(v9, v39);
    v96 = -1;
    v29 = ((_DWORD)v44 + 64) | (unsigned int)v39;
    v55 = -(__int64)(v37 * v39);
    v95 = 1061109567;
    v56 = (unsigned int)(v40 - v55);
    v27 = v46 - v55;
    v94 = 0;
    v58 = v51 & v50;
    while ( 1 )
    {
      v59 = v56 & v29;
      v36 = (unsigned int)(((_DWORD)v36 + 3425) << v5);
      LODWORD(v21) = v21 - 1300;
      v53 = (unsigned int)(v39 - 1360);
      if ( v94 >= 9 )
        break;
      v54 = v21 + v50;
      v25 |= v36;
      v50 += 2749;
      v57 = (unsigned int)v59 & (unsigned int)v29;
      v39 = v53 / v3;
      v32 = (unsigned int)(((int)v32 >> v54) - v25);
      v60 = (unsigned int)(v54 + v32);
      v61 = ((unsigned int)v27 >> v94) & (unsigned __int64)~v10;
      if ( (v99[v94 + 7] & 1) == 0 )
      {
        v52 |= v36;
        v30 |= v57;
        v58 = (unsigned __int64)v58 >> v55;
        v32 *= v60;
        v29 = (unsigned int)((int)v29 / (int)v36 + 1397 + v50);
        v60 *= v55;
        v10 = (unsigned int)v10 | (unsigned int)v58;
        v55 += v50;
        v25 |= v32;
        if ( v100[v94] <= v95 )
        {
          v61 /= v4;
          v50 = -(v50 * v58);
          v52 <<= v50;
          v32 += 16 * v60;
          v30 = (v30 & ~v39) * v58;
          v29 = (unsigned int)(v29 - 1483);
          v95 = v100[v94];
          v96 = v94;
          v57 = (((int)v57 >> v50) & (unsigned int)v55) / (unsigned int)v30;
        }
      }
      v56 = v57 & ~v61;
      v21 = v60 >> v60;
      v10 -= 2359;
      ++v94;
      v27 = (unsigned int)v61 ^ (unsigned int)v30 ^ (unsigned int)v39;
    }
    v9 = v32 + 4 * v50;
    v37 = (unsigned int)v55 & (unsigned int)v10;
    v38 = v53 - (v27 << 52);
    LODWORD(v27) = v27 - v9;
    LODWORD(v25) = v25 - 1864;
    v63 = v59 - (v29 << 44);
    v99[v96 + 7] = 1;
    v93 = 0;
    for ( i = v50 + v27 - 385; ; i = ((v65 & 1) << 17) & v21 )
    {
      v65 = (unsigned int)((i + 3449) / (int)v52);
      v66 = v58 + v9;
      v63 = v63 << 63 >> 10;
      LODWORD(v21) = v21 + v38;
      v25 = (unsigned int)((int)v25 / (int)v21);
      if ( v93 >= 9 )
        break;
      v35 = (unsigned int)v29 ^ (unsigned int)v10;
      v67 = v9 / v38;
      v68 = (unsigned __int64)(v10 & 1) << 25;
      v69 = v93;
      v27 = (unsigned int)(((int)v27 + (int)v68) / ((int)v27 + (int)v68));
      v70 = (unsigned int)v37 & (unsigned int)v52;
      v29 = v35 | v36;
      v58 = (unsigned int)(((int)v66 >> v2) / (int)v38);
      if ( (v99[v93 + 7] & 1) == 0 )
      {
        v27 += v38;
        v88 = ((unsigned int)__ROR8__(v67, v38) >> v93) & v38;
        v71 = (unsigned int)v63 / v96;
        v38 = (unsigned int)((int)v38 >> 31);
        v72 = v70 / v71;
        v63 = v71 / v27;
        v67 = v88 ^ (unsigned int)v72;
        v69 = v93;
        v68 = (unsigned int)(v68 - v30) - 29LL;
        v62 = (unsigned int)__ROR4__(36, 36 * v96) * v72;
        v70 = v72 - v27;
        v36 = v62 & ~v25;
        v29 = (unsigned int)__ROR4__(v29, v25);
        v58 = (unsigned int)(v58 - v21);
        if ( (*a1)[9 * v96 + v93] )
        {
          v69 = 1061109567;
          v63 = __ROR8__(v63, v67);
          v65 = (v65 & v58) * v27;
          v36 = v96;
          v68 >>= v30;
          v30 = (unsigned int)(v30 - 1602);
          v70 = (unsigned int)((__int64)v70 / v25) - (unsigned int)v67;
          LODWORD(v25) = v25 | v67;
          LODWORD(v27) = v27 ^ v25;
          if ( v100[v96] != 1061109567 )
          {
            v58 ^= v70;
            v65 /= v70;
            v73 = v67 * v65;
            LODWORD(v65) = v65 + __ROR4__(v52, (int)v21 / (int)v4);
            v74 = v38 & ~v58;
            v29 = (unsigned int)v29 / v74;
            v52 = 36LL * v96;
            v75 = (char *)*a1 + v52;
            v67 = (__int64)(v73 >> 36) / v52;
            LODWORD(v27) = (2 * v27 + 1673) & ~(_DWORD)v52;
            LODWORD(v52) = v93;
            LODWORD(v21) = v63 ^ 0x24;
            LODWORD(v75) = *(_DWORD *)&v75[4 * v93];
            v41 = v100[v96] + (_DWORD)v75;
            v30 = __ROR8__(v30, v29) >> (char)v75;
            LOBYTE(v65) = __ROR4__(v65 - 327, v70);
            v69 = (unsigned int)v100[v93];
            v38 = ((_DWORD)v74 + ((_DWORD)v29 << 11)) & (unsigned int)v27;
            v36 = (__int64)v93 << v69;
            v77 = v41 >= (unsigned int)v69;
            v63 = ((unsigned int)v63 & ~(_DWORD)v29) + (unsigned int)v27;
            if ( (v77 & 1) == 0 )
            {
              v69 = (__int64)v100;
              v58 = (unsigned int)((v58 >> v77) / v77) + 99;
              v78 = v65 + v63 + 55;
              v79 = (unsigned int)((int)(v29 | v30) / (int)v30);
              LODWORD(v21) = 36;
              v63 = (unsigned int)(v63 + v30) + 1658LL;
              v30 = (unsigned int)v30 ^ (unsigned int)v70;
              v27 = (unsigned __int64)((unsigned int)v27 ^ v93) << v70;
              LODWORD(v52) = v93;
              v70 = ((v70 & 1) << 31) ^ v27;
              LOBYTE(v65) = v78 + 115;
              v29 = (v79 & ~v79) + 2107;
              LODWORD(v25) = (int)v25 / 36;
              v36 = v93;
              v38 ^= 0x24uLL;
              v100[v93] = v100[v96] + (*a1)[9 * v96 + v93];
              LODWORD(v67) = v67 & v93;
            }
          }
        }
      }
      v10 = v68 ^ v36;
      v36 &= ~v70;
      v9 = (unsigned int)(v67 - v38 - v38);
      ++v93;
      v37 = v70 + v69;
    }
    v40 = (unsigned int)v63 >> v21;
    v10 <<= v21;
    v13 = v52 + v40;
    v39 = v38 & v66;
    ++v97;
    v42 = (int)v65 >> v40;
    v89 = (unsigned int)v66 / (unsigned int)v30;
  }
  v80 = v46 & v50;
  v92 = 0;
  v83 = v40 >> v17;
  while ( 1 )
  {
    v84 = (v10 & 1) << 7;
    v85 = (unsigned int)(v39 + 2165);
    if ( v92 >= 9 )
      break;
    v86 = (unsigned int)((int)(v44 >> v92) >> (v84 & ~(_BYTE)v30));
    LODWORD(v39) = printf(
                     v99,
                     v86 / v85,
                     v80 & (unsigned int)v83 ^ (unsigned __int64)(v86 / v85),
                     (unsigned int)v92,
                     (unsigned int)v100[v92]);
    v80 = v76 - v39;
    ++v92;
  }
  return -(v85 * v101);
}
