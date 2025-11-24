# ----------------------------------------------------------------------
# fastmath-all.asm - 68000 assembly routines for FastMath32
#
# License:
#   This file is licensed under the GNU General Public License v3.0 (GPL-3.0).
#   You may redistribute and/or modify it under the terms of the GPL as
#   published by the Free Software Foundation, either version 3 of the License,
#   or (at your option) any later version.
#
#   This file is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author:
#   Stefan "Bebbo" Franke <stefan@franke.ms>
#
# Contents:
#   - FastMath32::add  (multi-precision addition)
#   - FastMath32::sub  (multi-precision subtraction)
#
# Notes:
#   - Designed for Motorola 68000 (680x0 family).
#   - Uses addx.l / subx.l for carry propagation.
# ----------------------------------------------------------------------

__ZN10FastMath323addEPjPKjiS2_i: .globl __ZN10FastMath323addEPjPKjiS2_i
__ZN10FastMath323addEPmPKmiS2_i: .globl __ZN10FastMath323addEPmPKmiS2_i

    movem.l d2/d3/a2,-(sp)        | Save registers
    cmp.l   d0,d1                 | Compare lengths (al vs bl)
    bpl     .min                  | If al >= bl, skip swap
    exg     d0,d1                 | Swap lengths
    exg     a1,a2                 | Swap pointers
.min:

    move.l  d0,d2                 | d2 = min length
    moveq   #0,d0                 | d0 = return value (carry)

    sub.l   d2,d1                 | d1 = remaining length
    subq    #1,d2                 | convert to dbra style
    bmi     .Done1                | skip if no overlap

.Loop1:
    add.l   (a1)+,d0              | add a[i] + carry
    moveq   #0,d3
    addx.l  d3,d3                 | d3 = carry (0 or 1)
    add.l   (a2)+,d0              | add b[i]
    move.l  d0,(a0)+              | store result
    moveq   #0,d0
    addx.l  d3,d0                 | propagate carry (0 or 1)
    dbf     d2,.Loop1             | loop

.Done1:
    subq    #1,d1                 | remaining length-1
    bmi     .Done2                | if none, exit

.Loop2:
    add.l   (a2)+,d0              | add remaining b[i] + carry
    move.l  d0,(a0)+              | store result
    moveq   #0,d0
    addx.l  d0,d0                 | propagate carry
    dbf     d1,.Loop2             | loop

.Done2:
    movem.l (sp)+,d2/d3/a2        | restore registers
    rts                           | return


__ZN10FastMath323subEPjPKjiS2_i: .globl __ZN10FastMath323subEPjPKjiS2_i
__ZN10FastMath323subEPmPKmiS2_i: .globl __ZN10FastMath323subEPmPKmiS2_i

| FastMath32::sub function in 68000 assembly
| Inputs:
|   a0 = res (pointer to result array)
|   a1 = a   (pointer to first input array)
|   d0 = al  (length of a)
|   a2 = b   (pointer to second input array)
|   d1 = bl  (length of b)
| Output:
|   d0 = return value (1 if borrow, 0 otherwise)

    movem.l d2-d6/a2,-(sp)        | Save registers

    move.l  #0,d6                 | d6 = carrylo
    move.l  #0,d4                 | d4 = carryhi
    move.l  d0,d2                 | d2 = al
    move.l  d1,d3                 | d3 = bl

    cmp.l   d2,d3                 | find min(al, bl)
    ble.s   min_done
    move.l  d2,d3                 | d3 = min length
min_done:

    subq.l  #1,d3                 | convert to dbra style
    bmi.s   main_loop_done        | skip if zero

    moveq   #0,d5
main_loop:
    add.l   (a1)+,d6              | d6 = carrylo + a[i]
    addx.l  d5,d4                 | add overflow to carryhi
    sub.l   (a2)+,d6              | subtract b[i]
    subx.l  d5,d4                 | subtract overflow from carryhi
    move.l  d6,(a0)+              | store result

    move.l  d4,d6                 | carrylo = carryhi
    smi     d4                    | set carryhi (sign)
    ext.w   d4
    ext.l   d4

    dbf     d3,main_loop          | loop

main_loop_done:
    cmp.l   d0,d1                 | compare al vs bl
    blt.s   check_a_remain        | if al < bl, handle b remainder

    sub.l   d0,d1                 | remaining count
    subq.l  #1,d1
    bmi.s   done

b_loop:
    sub.l   (a2)+,d6              | subtract b[i]
    subx.l  d5,d4                 | subtract overflow
    move.l  d6,(a0)+              | store result

    move.l  d4,d6                 | carrylo = carryhi
    smi     d4
    ext.w   d4
    ext.l   d4

    dbf     d1,b_loop             | loop
    bra.s   done

check_a_remain:
    sub.l   d1,d0                 | remaining count (al - processed)
    subq.l  #1,d0
    bmi.s   done

a_loop:
    add.l   (a1)+,d6              | add a[i]
    addx.l  d5,d4                 | add overflow
    move.l  d6,(a0)+              | store result

    move.l  d4,d6                 | carrylo = carryhi
    smi     d4
    ext.w   d4
    ext.l   d4

    dbf     d0,a_loop             | loop

done:
    move.l  d4,d0                 | set return value from carry
    neg.l   d0                    | normalize to 0/1

    movem.l (sp)+,d2-d6/a2        | restore registers
    rts                           | return
