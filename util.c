/*
 * 
 * Various Utilities
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen	
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "util.h"
#include <stdio.h>

void num_to_bytes(uint64_t n, size_t len, byte_t* dst)
{
  while (len--)
  {
    dst[len] = (byte_t)n;
    n >>= 8;
  }
}

void print_bytes(const byte_t* pbtData, const size_t szLen)
{
  size_t uiPos;
  for (uiPos=0; uiPos < szLen; uiPos++)
  {
    printf("%02x ",pbtData[uiPos]);
    if (uiPos>20)
    {
      printf("...");
      break;
    }
  }
  printf("\n");
}
