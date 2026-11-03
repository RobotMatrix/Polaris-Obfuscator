__int64 __fastcall shortestPath(__int64 result, int a2)
{
  int n; // [xsp+20h] [xbp-60h]
  int m; // [xsp+24h] [xbp-5Ch]
  int k; // [xsp+28h] [xbp-58h]
  unsigned int v5; // [xsp+2Ch] [xbp-54h]
  int v6; // [xsp+30h] [xbp-50h]
  int j; // [xsp+34h] [xbp-4Ch]
  int i; // [xsp+38h] [xbp-48h]
  _BYTE v9[45]; // [xsp+4Bh] [xbp-35h]

  for ( i = 0; i < 9; ++i )
  {
    *(_DWORD *)&v9[4 * i + 9] = 1061109567;
    v9[i] = 0;
  }
  *(_DWORD *)&v9[4 * a2 + 9] = 0;
  for ( j = 0; j < 8; ++j )
  {
    v6 = -1;
    v5 = 1061109567;
    for ( k = 0; k < 9; ++k )
    {
      if ( (v9[k] & 1) == 0 && *(_DWORD *)&v9[4 * k + 9] <= v5 )
      {
        v5 = *(_DWORD *)&v9[4 * k + 9];
        v6 = k;
      }
    }
    v9[v6] = 1;
    for ( m = 0; m < 9; ++m )
    {
      if ( (v9[m] & 1) == 0
        && *(_DWORD *)(result + 36LL * v6 + 4LL * m)
        && *(_DWORD *)&v9[4 * v6 + 9] != 1061109567
        && (unsigned int)(*(_DWORD *)&v9[4 * v6 + 9] + *(_DWORD *)(result + 36LL * v6 + 4LL * m)) < *(_DWORD *)&v9[4 * m + 9] )
      {
        *(_DWORD *)&v9[4 * m + 9] = *(_DWORD *)&v9[4 * v6 + 9] + *(_DWORD *)(result + 36LL * v6 + 4LL * m);
      }
    }
  }
  for ( n = 0; n < 9; ++n )
    result = printf("%d\t%u\n", n, *(_DWORD *)&v9[4 * n + 9]);
  return result;
}
