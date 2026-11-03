__int64 __fastcall shortestPath(
        unsigned __int64 a1,
        __int64 a2,
        int a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        int a7,
        char a8)
{
  int v8; // w9
  __int64 v9; // x11
  int v10; // w12
  int v11; // w13
  unsigned int v12; // w14
  __int64 v13; // x15
  char v14; // w16
  char v15; // w21
  char v16; // w24
  char v17; // w27
  __int64 v18; // x11
  __int64 v19; // x4
  __int64 v20; // x9
  __int64 v21; // x5
  __int64 v22; // x0
  __int64 v23; // x6
  __int64 v24; // x1
  __int64 v25; // x15
  unsigned __int64 v26; // x7
  int v27; // w13
  unsigned __int64 v28; // x12
  unsigned __int64 v29; // x0
  __int64 v30; // x11
  __int64 v31; // x14
  char v32; // w5
  __int64 v33; // x2
  __int64 v34; // x3
  int v35; // w4
  __int64 v36; // x3
  int v37; // w12
  int v38; // w9
  __int64 v39; // x11
  __int64 v40; // x10
  unsigned int v41; // w6
  signed __int64 v42; // x0
  unsigned __int64 v43; // x9
  __int64 v44; // x2
  unsigned __int64 v45; // x1
  __int64 v46; // x7
  __int64 v47; // x8
  unsigned int v48; // w6
  signed __int64 v49; // x10
  __int64 v50; // x12
  unsigned int v51; // w13
  __int64 v52; // x11
  unsigned int v53; // w6
  __int64 v54; // x9
  __int64 v55; // x5
  __int64 v56; // x13
  unsigned __int64 v57; // x7
  int v58; // w1
  __int64 v59; // x7
  __int64 v60; // x2
  __int64 v61; // x2
  int v62; // w10
  unsigned int v63; // w10
  unsigned int v64; // w8
  __int64 v65; // x1
  __int64 v66; // x9
  unsigned int v67; // w2
  __int64 v68; // x7
  int v69; // w2
  int v70; // w13
  __int64 v71; // x2
  __int64 v72; // x9
  __int64 v73; // x11
  __int64 v74; // x5
  unsigned int v75; // w6
  __int64 v76; // x9
  bool v77; // cf
  bool v78; // w8
  __int64 result; // x0
  int v80; // w5
  __int64 v81; // x4
  int v82; // [xsp+20h] [xbp-60h]
  int v83; // [xsp+24h] [xbp-5Ch]
  int v84; // [xsp+28h] [xbp-58h]
  unsigned int v85; // [xsp+2Ch] [xbp-54h]
  int v86; // [xsp+30h] [xbp-50h]
  int v87; // [xsp+34h] [xbp-4Ch]
  int v88; // [xsp+38h] [xbp-48h]
  int v89; // [xsp+3Ch] [xbp-44h]
  _BYTE v91[9]; // [xsp+4Bh] [xbp-35h] BYREF
  _DWORD v92[9]; // [xsp+54h] [xbp-2Ch] BYREF

  v18 = v9 + a5;
  v19 = (unsigned int)(a5 + 1391);
  v20 = (unsigned int)(v8 + v19);
  v21 = a6 >> a1;
  v23 = (unsigned int)((a7 + 2647) >> a8);
  v69 = (int)(a3 & a4) >> a1;
  v25 = (v13 + 1056) & ~v18;
  v26 = ((unsigned __int64)(a8 & 1) << 6) + v21;
  v28 = v10 & v12 | v26;
  LODWORD(v18) = v18 + v28;
  v68 = (unsigned int)(v26 + v18);
  v89 = a2;
  v30 = (unsigned int)(v18 - v68);
  v88 = 0;
  v31 = -(-(__int64)((unsigned int)((int)((((v12 & 1) << 12) + 80) | v11) / (int)v20) * v28) * v19);
  v32 = v21 + 65;
  v81 = (unsigned int)((_DWORD)v19 << a2);
  while ( 1 )
  {
    v33 = (unsigned int)(v69 + 2629);
    v24 = a2 & v23;
    v34 = (unsigned int)(a4 - 968);
    if ( v88 >= 9 )
      break;
    v35 = (v81 << 63 >> 15) | v31;
    v36 = v34 >> v68;
    v31 = -(v31 * v20);
    v59 = (unsigned int)v68 ^ (unsigned int)v24;
    v60 = v33 - 5172;
    v25 += 1546;
    v92[v88] = 1061109567;
    v37 = v28 - v59;
    v38 = v88;
    v68 = v59 & ~v60;
    v28 = v37 ^ (unsigned int)v31;
    a4 = (unsigned int)(v36 + v30);
    LODWORD(v60) = v60 ^ v88;
    v91[v88] = 0;
    a2 = ((unsigned int)v24 & (unsigned int)v60) + 3938LL;
    v23 = (unsigned int)(v23 - v60) - 220LL;
    v69 = v60 * v25;
    v81 = (unsigned int)(v35 - v28);
    ++v88;
    v30 = -((v30 + a2) * a4);
    v20 = (unsigned int)(v38 << a2) + 111LL;
  }
  v39 = (unsigned int)(v30 - v28);
  v40 = v89;
  v41 = v23 - v39;
  v80 = (v32 & 1) << 21;
  v50 = v28 << a1;
  v42 = a1 & v81;
  v92[v89] = 0;
  LOBYTE(v81) = v81 - v31;
  v43 = (unsigned int)((int)v92 >> (char)v92);
  v87 = 0;
  v44 = (unsigned int)(v33 + v11);
  while ( 1 )
  {
    v45 = v24 ^ v39;
    LODWORD(v56) = 0;
    v46 = v68 & v43;
    v47 = v87 >= 8;
    v81 = (unsigned __int64)(v81 & 1) << 40;
    if ( v87 >= 8 )
      break;
    v31 = __ROR8__(v31, v14);
    v48 = v41 >> v45;
    v25 += 1585;
    v29 = v42 - 2120;
    v61 = v44 / v46;
    v65 = v45 / v29;
    v86 = -1;
    v85 = 1061109567;
    v54 = __ROR8__(0xFFFFFFFFLL, v34) >> v39;
    v55 = v80 & (unsigned int)v81 & (unsigned int)v54;
    v84 = 0;
    v53 = v48 - ((_DWORD)v39 << 15);
    while ( 1 )
    {
      v31 &= v29;
      v51 = v56 & v46;
      v40 /= v54;
      v24 = v65 & ~v55;
      if ( v84 >= 9 )
        break;
      v52 = v39 / 0;
      v53 += v34;
      v54 = v84;
      v55 &= v81;
      v49 = (unsigned __int64)(v40 - 3046) >> v15;
      LODWORD(v50) = (_DWORD)v50 << v84;
      v56 = v51 + (unsigned int)v31;
      v57 = (unsigned __int64)v46 >> v14;
      v58 = v24 + 840;
      if ( (v91[v84] & 1) == 0 )
      {
        v25 ^= v56;
        v81 = v81 << 63 >> 47;
        LODWORD(v34) = v34 * v81;
        v56 >>= v50;
        v61 = (unsigned int)v61 >> v34;
        v52 -= 2096;
        v54 = v85;
        v31 = (unsigned int)(v31 + 379);
        v57 -= v61;
        v58 += 1067;
        LODWORD(v61) = v61 - v49;
        if ( v92[v84] <= v85 )
        {
          LODWORD(v61) = v61 ^ v31;
          v62 = v49 + v55;
          LODWORD(v50) = v50 - ((_DWORD)v57 << 27);
          v25 = v25 - 3120 + v31;
          v53 <<= v50;
          v55 = (unsigned int)(v55 - v84);
          v49 = v62 & (unsigned int)v25;
          v85 = v92[v84];
          v31 += v55;
          v54 = __ROR8__(v84, v49);
          v86 = v84;
          LODWORD(v56) = __ROR4__(v56, v50);
        }
      }
      v39 = v52 & v49;
      v65 = (unsigned int)(v58 >> v49);
      v29 = (unsigned int)v29 / (unsigned int)v57;
      v40 = v49 / v65;
      ++v84;
      v46 = v57 - 1998;
      LODWORD(v61) = v61 + 2849;
    }
    v50 = (unsigned int)v50 / (unsigned int)v24;
    v68 = (unsigned int)v46 / (unsigned int)v50;
    LODWORD(v29) = v29 - 3582;
    LODWORD(v55) = v55 + 1752;
    v66 = (__int64)&v91[v86];
    v34 = (unsigned int)((_DWORD)v34 << v66);
    *(_BYTE *)v66 = 1;
    v83 = 0;
    v67 = ((int)v61 + (int)v31) / (unsigned int)v29;
    while ( 1 )
    {
      v25 = (((_DWORD)v25 - (_DWORD)v81) & v51) + 1742;
      v24 <<= v66;
      v70 = 0;
      v71 = v67 - v50;
      if ( v83 >= 9 )
        break;
      v34 = (unsigned int)v34 | (unsigned int)v39;
      v72 = v83;
      v73 = (unsigned int)(v39 - 2724);
      v74 = (unsigned int)v55 & (unsigned int)v73;
      v31 = v31 << 63 >> 23;
      v40 <<= v15;
      LODWORD(v29) = __ROR4__(v29 & v71, v83);
      LODWORD(v81) = (int)v81 / (int)v74;
      v55 = v74 + v83;
      if ( (v91[v83] & 1) == 0 )
      {
        v71 = (unsigned int)(v71 + v68);
        v40 = 36;
        v68 = (unsigned int)(v68 - v25);
        LODWORD(v81) = 0;
        v55 = ((__int64)(v55 - ((unsigned __int64)(unsigned int)v29 << 42)) / (unsigned int)v29) ^ v50;
        v34 = (unsigned int)v34 ^ (unsigned int)v29;
        v50 = (unsigned int)v50 & (unsigned int)v31;
        v72 = v83 - v73;
        LODWORD(v29) = v29 + 1149;
        LODWORD(v55) = (v55 ^ v24) - v68;
        if ( *(_DWORD *)(a1 + 36LL * v86 + 4LL * v83) )
        {
          v31 -= v34;
          v50 += v25 << 59;
          v72 = 1061109567;
          v71 /= v68;
          v40 = v86;
          v29 = ((_DWORD)v29 + (_DWORD)v71) | v53;
          LODWORD(v25) = v25 + v34 + v68;
          LODWORD(v71) = v71 | 0x3F3F3F3F;
          v70 = -(int)v55;
          if ( v92[v86] != 1061109567 )
          {
            v75 = v53 - 3715;
            v25 = ((unsigned int)v25 & (unsigned int)v34) + 2047;
            v34 = (unsigned int)v34 ^ (unsigned int)v71;
            v27 = (v70 & v75) - 832;
            v29 = -(__int64)((v29 & v68) * v24);
            v53 = __ROR4__(v75 + 724, v27);
            v68 = (v68 & 0x24) + v29;
            LODWORD(v71) = v71 + 704;
            v63 = *(_DWORD *)(a1 + 36LL * v86 + 4LL * v83);
            v24 += v68;
            v64 = v92[v86] + v63;
            LODWORD(v29) = v29 & v63;
            v31 = (unsigned int)v31 ^ (unsigned int)v71;
            v40 = v83;
            v50 = 1901;
            LODWORD(v29) = v29 + v53;
            v76 = (unsigned int)v92[v83];
            LODWORD(v73) = v83 - v68;
            v77 = v64 >= (unsigned int)v76;
            v72 = v76 << 63 >> 5;
            LODWORD(v81) = 0;
            v78 = v77;
            v70 = 257 * v27;
            if ( !v78 )
            {
              v72 = (__int64)v92;
              v29 = (__int64)((unsigned int)v29 & (unsigned int)v73) >> ((unsigned __int8)v29 & (unsigned __int8)v73);
              LODWORD(v55) = __ROR4__(v55, 36);
              v34 = (unsigned int)(v34 + v31 + 4707);
              v70 = ((v70 - v29) | v31) - v29;
              LOBYTE(v73) = v83;
              LODWORD(v29) = v29 + 748;
              v25 = (__ROR8__(v25, v17) << (char)v92) - 2330LL;
              LODWORD(v68) = v68 & v55 & ~v70;
              v81 = (__int64)&stru_100000020.fileoff + 2;
              v40 = v83;
              v53 /= (unsigned int)v92;
              v92[v83] = v92[v86] + *(_DWORD *)(a1 + 36LL * v86 + 4LL * v83);
              v50 = 36LL >> v83;
            }
          }
        }
      }
      v68 = (unsigned int)v68 >> v34;
      v66 = v72 / v34;
      v51 = v70 + v71 - 1170;
      v67 = v71 & v55;
      ++v83;
      v39 = (unsigned __int64)(v73 & 1) << 50;
    }
    v43 = (unsigned __int64)(v66 & 1) << 40;
    v80 = (int)v55 >> v16;
    v44 = v71 - v34;
    v42 = (unsigned int)(((int)v29 - 3991) / (int)v24);
    ++v87;
    v41 = v53 ^ v25;
  }
  v82 = 0;
  v22 = v42 / v47;
  while ( 1 )
  {
    result = v22 << v47;
    if ( v82 >= 9 )
      break;
    v22 = printf("%d\t%u\n", v82, v92[v82]);
    LOBYTE(v47) = ++v82;
  }
  return result;
}
