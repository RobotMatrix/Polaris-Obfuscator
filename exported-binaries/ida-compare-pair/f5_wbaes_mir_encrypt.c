__int64 __fastcall WBAES::encrypt(
        unsigned __int64 this,
        unsigned __int64 a2,
        __int64 a3,
        int a4,
        __int64 a5,
        int a6,
        __int64 a7,
        int a8)
{
  int v8; // w9
  int v9; // w10
  int v10; // w12
  __int64 v11; // x13
  int v12; // w14
  __int64 v13; // x15
  unsigned __int64 v14; // x16
  char v15; // w22
  unsigned __int64 v16; // x24
  __int64 v17; // x6
  unsigned __int64 v18; // x12
  __int64 v19; // x5
  __int64 v20; // x13
  __int64 v21; // x0
  __int64 v22; // x13
  unsigned __int64 v23; // x6
  __int64 v24; // x1
  unsigned __int64 v25; // x7
  unsigned int v26; // w10
  int v27; // w4
  __int64 v28; // x1
  __int64 v29; // x9
  unsigned __int64 v30; // x13
  int v31; // w12
  int v32; // w9
  unsigned __int64 v33; // x4
  unsigned __int64 v34; // x6
  __int64 v35; // x9
  __int64 v36; // x15
  unsigned __int64 v37; // x4
  __int64 v38; // x10
  unsigned __int64 v39; // x14
  __int64 v40; // x5
  unsigned __int64 v41; // x7
  unsigned int v42; // w3
  unsigned int v43; // w12
  __int64 v44; // x13
  __int64 v45; // x5
  unsigned __int64 v46; // x3
  __int64 v47; // x14
  unsigned __int64 v48; // x7
  __int64 v49; // x2
  unsigned __int64 v50; // x15
  unsigned __int64 v51; // x14
  __int64 v52; // x13
  int v53; // w12
  __int64 v54; // x10
  __int64 v55; // x12
  unsigned __int64 v56; // x0
  __int64 v57; // x2
  __int64 v58; // x2
  unsigned int v59; // w10
  __int64 v60; // x13
  int v61; // w3
  __int64 v62; // x11
  __int64 v63; // x4
  unsigned __int64 v64; // x3
  unsigned __int64 v65; // x4
  __int64 v66; // x12
  char v67; // w8
  int v68; // w1
  unsigned __int64 v69; // x2
  unsigned __int64 v70; // x15
  __int64 v71; // x5
  __int64 v72; // x13
  int v73; // w6
  __int64 v74; // x4
  int v75; // w0
  char *v76; // x9
  __int64 v77; // x11
  __int64 v78; // x2
  unsigned __int64 v79; // x7
  int v80; // w6
  __int64 v81; // x0
  char *v82; // x9
  unsigned __int64 v83; // x4
  __int64 v84; // x0
  unsigned __int64 v85; // x4
  unsigned __int64 v86; // x0
  __int64 v87; // x3
  unsigned int v88; // w0
  __int64 v89; // x12
  __int64 v90; // x14
  __int64 v91; // x5
  __int64 v92; // x0
  unsigned __int64 v93; // x7
  __int64 v94; // x5
  unsigned __int64 v95; // x4
  __int64 v96; // x7
  __int64 v97; // x1
  __int64 v98; // x13
  __int64 v99; // x12
  __int64 v100; // x4
  __int64 v101; // x11
  __int64 v102; // x6
  unsigned __int64 v103; // x3
  int v104; // w3
  __int64 v105; // x6
  unsigned __int64 v106; // x1
  __int64 v107; // x5
  int v108; // w10
  __int64 v109; // x13
  __int64 v110; // x12
  __int64 v111; // x3
  unsigned __int64 v112; // x4
  char *v113; // x9
  unsigned __int64 v114; // x15
  __int64 v115; // x13
  __int64 v116; // x6
  __int64 v117; // x11
  __int64 v118; // x4
  char *v119; // x8
  int v120; // w9
  __int64 v121; // x5
  unsigned __int64 v122; // x14
  int v123; // w6
  unsigned __int64 v124; // x0
  unsigned __int64 v125; // x7
  unsigned __int64 v126; // x1
  __int64 v127; // x0
  unsigned __int64 v129; // [xsp+0h] [xbp-80h]
  unsigned __int8 v130; // [xsp+Fh] [xbp-71h]
  int v131; // [xsp+10h] [xbp-70h]
  int v132; // [xsp+14h] [xbp-6Ch]
  int v133; // [xsp+18h] [xbp-68h]
  int v134; // [xsp+20h] [xbp-60h]
  int v135; // [xsp+24h] [xbp-5Ch]
  int v136; // [xsp+28h] [xbp-58h]
  int v137; // [xsp+2Ch] [xbp-54h]
  int v138; // [xsp+30h] [xbp-50h]
  int v139; // [xsp+34h] [xbp-4Ch]
  __int64 v140; // [xsp+38h] [xbp-48h]
  __int128 v141; // [xsp+50h] [xbp-30h] BYREF
  __int128 v142; // [xsp+60h] [xbp-20h] BYREF

  v17 = a7 << this;
  v18 = v10 | (unsigned int)v13;
  v19 = (__int64)((unsigned __int64)(unsigned int)((a6 + v9) / a4) << 63) >> 63;
  v32 = __ROR4__(v8 - 3313 - a8, this);
  LODWORD(v41) = a8 & a5 & v17;
  v35 = (unsigned int)(v32 >> v41);
  v36 = v13 - v35;
  v37 = ((unsigned int)(a5 << 63 >> 8) / (unsigned int)v16) ^ a2;
  v140 = a3;
  v38 = (unsigned int)(v9 >> v11 << v41);
  v39 = (unsigned int)(v12 << a4) + (v37 << 10);
  v40 = (unsigned int)v19 & (unsigned int)v18;
  v129 = this;
  v41 = (unsigned int)v41;
  v61 = (a4 - v11) & v11;
  v62 = (unsigned int)v36;
  v63 = (unsigned int)((_DWORD)v37 << v17);
  v51 = v39 + v63;
  v142 = *(_OWORD *)a2;
  v52 = v11 - (unsigned int)v36;
  v64 = (v61 << this) & (unsigned int)a2;
  v139 = 0;
  v65 = (unsigned int)v63 & (unsigned int)v17;
  while ( 1 )
  {
    v20 = v52 - (v65 << 29);
    v21 = (unsigned int)((_DWORD)this << v20);
    LODWORD(v23) = 0;
    v24 = a2 - 3047 + v64;
    v52 = __ROR8__(v20, v62);
    if ( v139 >= 4 )
      break;
    v103 = v64 / v16;
    v62 = (unsigned int)__ROR4__(v62, v15);
    this = v21 - v18;
    v138 = 0;
    v25 = v41 / v18;
    while ( 1 )
    {
      v26 = v38 + v62;
      v27 = v65 | v25;
      v28 = (unsigned int)((_DWORD)v24 << v27);
      v29 = v35 - (this << 59);
      v65 = (unsigned int)(v27 >> v52);
      if ( v138 >= 4 )
        break;
      v24 = v28 + 1202;
      v30 = v52 + v103;
      v51 &= ~a3;
      v86 = this >> this;
      v31 = v18 - a3;
      v38 = g_wb_ark0[4 * v139 + v138];
      v112 = __ROR8__((unsigned int)(v65 * v36 - v31), v86) << v30;
      v119 = (char *)&v142 + 4 * v139;
      v62 = (unsigned int)((int)((unsigned int)((int)(v62 >> v14) >> v38) / (unsigned __int64)v139) >> v31);
      v113 = &v119[v138];
      v114 = (unsigned __int64)(unsigned int)(((int)v36 - 2112) / v31) << ((unsigned __int8)v119 + (unsigned __int8)v138);
      v65 = v112 / v38;
      v52 = (v30 & v24) + 883;
      *v113 ^= v38;
      v18 = 0;
      v35 = (unsigned int)(((int)v113 >> v86) + 1253);
      v103 = 0;
      v36 = (unsigned int)(v114 + 182 + v40);
      ++v138;
      this = v86 + v51;
      LODWORD(v23) = 116 >> v52;
    }
    v64 = v103 - 2253;
    v41 = v25 - 1068;
    v18 *= v28;
    v35 = v29 - v36;
    v38 = (v26 / (unsigned int)v52) & (unsigned int)v23;
    ++v139;
    v40 = __ROR8__(v40, v52);
    a2 = v28 - 54;
  }
  v54 = v38 >> v15;
  v137 = 0;
  v44 = (unsigned int)v52 & (unsigned int)v54;
  while ( 1 )
  {
    LODWORD(v23) = v23 | v41;
    LODWORD(v21) = v21 - 3378;
    v45 = v40 & ~v24;
    v44 *= v24;
    v42 = v64 - 3792;
    if ( v137 >= 9 )
      break;
    v43 = v18 - 1630;
    v23 = (unsigned int)(v23 - 319);
    v35 = (unsigned int)v35;
    v136 = 0;
    v46 = v42 >> v54;
    v47 = (__int64)(v51 << 63) >> 45;
    while ( 1 )
    {
      v48 = v41 - (v35 << 61);
      v49 = a3 + v65;
      LODWORD(v54) = v54 + v49;
      v40 = v45 / 0;
      v33 = v65 & v35;
      if ( v136 >= 4 )
        break;
      v34 = v23 << (v136 >= 4);
      v41 = v48 << v34;
      v50 = v36 << 63 >> 18;
      v135 = 0;
      v53 = v43 ^ v49;
      v134 = 0;
      LOBYTE(v54) = v54 * v54 + 54;
      while ( 1 )
      {
        v55 = (unsigned int)(v53 << v54);
        v56 = (unsigned int)(v21 - v46);
        v57 = v49 | v50;
        if ( v134 >= 4 )
          break;
        v24 = ((unsigned int)v24 >> v56) + 3555LL;
        v47 = -(__int64)(v47 * v56) - (v41 << 39);
        v60 = -(__int64)(v44 * ((v46 / v129) & ~v24));
        v58 = (v57 >> v57) * v41;
        v59 = (v136 + v134) % 4;
        LODWORD(v24) = (((unsigned int)v24 & (unsigned int)v56) / (unsigned int)v34) & ~(_DWORD)v33;
        v50 = (__int64)(v50 / v56) / 4 - 1420;
        v76 = (char *)&v142 + 4 * (int)v59;
        v77 = 4 / v59;
        v40 = (unsigned int)(v40 - v34) - 271LL;
        v109 = (unsigned int)v60 | (unsigned int)v41;
        v110 = v55 ^ v40;
        v33 = (unsigned int)v33 ^ (unsigned int)v41;
        v21 = ((unsigned int)((int)v56 >> v56) + v40) >> v134;
        v79 = 2 * v41 + (v77 << 38);
        LODWORD(v77) = v77 - 3096;
        v46 = ((unsigned int)((int)v40 / (int)v24) & (unsigned __int64)~v58) - 1542;
        v49 = (unsigned int)v58 & (unsigned int)v77;
        v54 = ((unsigned __int64)(unsigned int)(2 * v134) >> v77) + (v110 << 14);
        v135 ^= *(_DWORD *)(v129
                          + ((__int64)v137 << 14)
                          + ((__int64)v134 << 12)
                          + ((__int64)v136 << 10)
                          + 4LL * (unsigned __int8)v76[v134]);
        v44 = v109 - 3749;
        v67 = v134;
        LODWORD(v24) = (v24 & v21) + 1443;
        v53 = v110 & v49;
        ++v134;
        v41 = (2 * ((unsigned int)(v79 >> v79) + (unsigned int)v49)) >> (v67 + 1);
        v34 = (((unsigned int)(v34 >> v129) - (unsigned int)v40) << ((v34 >> v129) - v40)) + (v41 << 19);
      }
      v22 = 2 * v44;
      v68 = v24 & v57;
      v122 = v47 - v50;
      *((_BYTE *)&v141 + 4 * v136) = HIBYTE(v135);
      v123 = v34 & v50;
      v69 = (unsigned __int64)v57 >> v123;
      v70 = v50 - (v40 << 38);
      v75 = v56 - 341 - (v123 << 16);
      v71 = __ROR8__(v40, v22);
      v72 = v22 | v71;
      v65 = (unsigned int)(v33 / v41) | (unsigned int)v69;
      *((_BYTE *)&v141 + 4 * v136 + 1) = BYTE2(v135);
      v45 = v71 + 1818;
      v44 = v72 + v136;
      v73 = v123 + v136;
      v47 = v122 & ~v70 & v44;
      LODWORD(v70) = v70 ^ v46;
      v46 -= 223LL;
      LODWORD(v70) = v70 + v73;
      v80 = v73 & v75;
      v81 = v75 & (unsigned int)v136;
      *((_BYTE *)&v141 + 4 * v136 + 2) = BYTE1(v135);
      LODWORD(v70) = v70 + 1299 - v81;
      LODWORD(v54) = v136;
      v21 = v81 << v136;
      v62 = v136 - v47;
      v82 = (char *)&v141 + 4 * v136;
      v43 = (unsigned int)(v55 + 5315) >> v70;
      v82[3] = v135;
      v36 = (unsigned int)(v70 - v21);
      v24 = (unsigned int)__ROR4__(v68 + 30, v44);
      LODWORD(v69) = v69 & (unsigned int)v82;
      v23 = (v80 ^ v136) - (unsigned int)v44 + 3450;
      v35 = (unsigned int)v82 / (unsigned int)v24;
      ++v136;
      v47 = (unsigned int)v47;
      a3 = (unsigned int)(v69 - v45);
    }
    v83 = v33 - 809;
    v51 = v47 >> v14;
    v142 = v141;
    v64 = (unsigned int)v46 & (unsigned int)v35;
    v36 = (v36 + 4054) & v49;
    v24 &= ~v23;
    LODWORD(v18) = v43 << v49;
    v41 = (unsigned int)__ROR4__(v48 + ((_DWORD)v54 << 22), v83);
    ++v137;
    v65 = v83 + v64;
    a3 = v49 >> v51;
  }
  LODWORD(v87) = v42 - v18;
  v133 = 0;
  v88 = v21 ^ v41;
  v91 = v45 >> v65;
  while ( 1 )
  {
    v92 = v88 / (unsigned int)v65;
    v93 = v41 - v91;
    v94 = v91 - v92;
    v95 = v65 - 309;
    v66 = (unsigned int)(v18 + v92);
    if ( v133 >= 4 )
      break;
    v51 = (unsigned int)v51 >> v16;
    v96 = -(__int64)(v93 * v51);
    v97 = (unsigned int)(v24 - v54);
    v132 = 0;
    v98 = v44 & v62;
    v99 = v66 | v97;
    v131 = 0;
    v100 = 1025 * v95;
    while ( 1 )
    {
      v101 = (unsigned int)(v62 - v100);
      v36 = (unsigned int)(v36 - v51 + v99);
      v102 = (unsigned int)((_DWORD)v23 << v92);
      v87 = (unsigned int)(v87 + v94);
      if ( v131 >= 4 )
        break;
      v104 = v87 & v51;
      v105 = v102 | v94;
      v89 = v99 >> v105;
      v90 = (unsigned int)((int)v51 / (int)v100);
      v106 = v97 + 1368;
      v107 = v94 + v90;
      v23 = (unsigned __int64)(v105 - v107) >> 4;
      v108 = (v133 + v131) % 4;
      LODWORD(v98) = (int)(v98 >> v92) / v108;
      v51 = v90 + 3804;
      v121 = v107 & ~v36;
      v124 = __ROR8__(v92, v100);
      v125 = (unsigned __int64)(unsigned int)((int)v96 / (int)v23) << v124;
      LODWORD(v36) = 0;
      v130 = *((_BYTE *)&v142 + 4 * v108 + v131);
      LODWORD(v23) = (v23 + 1072 - v106) & v98;
      v126 = v106 / v124;
      v127 = v124 - (v126 << 61);
      LODWORD(v23) = __ROR4__(v23, v133);
      v99 = v89 << v127;
      v118 = v100 & ~(__int64)v131;
      v120 = *(_DWORD *)(v129 + 147456 + ((__int64)v131 << 12) + ((__int64)v133 << 10) + 4LL * v130);
      v97 = 8 * (v126 & 1);
      v96 = (unsigned int)((int)v125 >> v120);
      LODWORD(v87) = __ROR4__(v104 | v51, v131) & v98;
      v132 ^= v120;
      v92 = v127 + (v97 << 58);
      LODWORD(a3) = (a3 + 3290) & ~(_DWORD)v87;
      v94 = (unsigned int)((v121 - v51) << v130) | (unsigned int)v92;
      ++v131;
      v100 = v118 >> v118;
      LODWORD(v62) = (v51 ^ 4) + v87;
    }
    v111 = v87 + v102 + (v101 << 32);
    v36 = (unsigned int)v36 | (unsigned int)a3;
    *(_BYTE *)(v140 + 4 * v133) = HIBYTE(v132);
    v115 = (unsigned int)v98 / (unsigned int)v96 + 2033;
    LODWORD(v51) = (v51 / v14) ^ (4 * v133);
    v116 = (unsigned int)(v102 + v99) - 811LL;
    v117 = (unsigned int)(4 * v133 + 1);
    v18 = v99 + 1610;
    v74 = (unsigned int)((int)(v100 | v97) >> v116 << (4 * v133 + 1));
    *(_BYTE *)(v140 + (int)v117) = BYTE2(v132);
    v41 = v96 ^ v116;
    v23 = v116 - (v117 + 1095);
    v24 = v97 - v36;
    v78 = ((unsigned int)a3 >> (4 * v133)) - 4859LL;
    v87 = (v111 ^ v36 ^ v115) << v78;
    *(_BYTE *)(v140 + 4 * v133 + 2) = BYTE1(v132);
    v84 = (unsigned int)((int)v92 / (int)v92 + v87);
    v85 = (((v74 + v18) & v41) << SBYTE1(v132)) * v24;
    v91 = (4294965085LL >> (4 * (unsigned __int8)v133)) + (v78 << 21) + v36;
    v44 = (__int64)(v115 + v18) >> v41;
    LODWORD(v54) = 4 * v133 + 3;
    *(_BYTE *)(v140 + (int)v54) = v132;
    a3 = __ROR8__(v78, v24) / v84;
    LODWORD(v24) = __ROR8__(v24 + (v85 << 56), v87) - v51;
    v62 = (unsigned int)v133 ^ (unsigned __int64)v36;
    v88 = v84 + v91;
    ++v133;
    v65 = v85 / v23;
    LODWORD(v36) = (v36 ^ v44) & v51;
  }
  return (unsigned int)(v92 + v66);
}
