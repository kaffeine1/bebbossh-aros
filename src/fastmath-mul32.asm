# ----------------------------------------------------------------------
# fastmath-mul32.asm - 68000 assembly routines for big integer arithmetic
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
#   - FastMath32_mul: schoolbook multiplication of two uint32_t arrays
#   - FastMath32_square: squaring routine for uint32_t arrays
#
# Notes:
#   - Uses mulu.l (32×32->64) where available.
#   - Carry propagation handled with addx.l.
#   - Designed for clarity, maintainability, and GPL distribution.
# ----------------------------------------------------------------------

| Input parameters:
| a0: dst (pointer to uint32_t array)
| a1: a   (pointer to uint32_t array)
| a2: b   (pointer to uint32_t array)
| d0: len (number of elements, assumed > 0)

__ZN10FastMath323mulEPjPKjS2_i: .globl __ZN10FastMath323mulEPjPKjS2_i
__ZN10FastMath323mulEPmPKmS2_i: .globl __ZN10FastMath323mulEPmPKmS2_i

    subq.l  #1,d0                 | Adjust len once here for dbra (len-1)
    blt     .done2                 | If len <= 0, exit
    movem.l d2-d7/a2-a5,-(sp)     | Save registers (d7 not needed later)

    move.l  a0,a3                 | a3 = dst base
    move.l  a1,a4                 | a4 = a pointer (autoincrement)
                                  | a2 = b base

    | First loop: i = 0 case
    move.l  (a4)+,d1              | d1 = a[0], increment a
    move.l  a2,a5                 | a5 = b pointer (autoincrement)
    moveq   #0,d6                 | carry = 0 (upper 32 bits)
    move.l  d0,d2                 | use pre-decremented counter

.first_loop:
    move.l  (a5)+,d3              | d3 = b[i], increment b
    mulu.l  d1,d5,d3              | emulate 64-bit product: d5:d3 = a[0]*b[i]

    add.l   d3,d6                 | add product low to carry
    move.l  d6,(a0)+              | store result, increment dst
    moveq   #0,d6                 | clear for carry propagation
    addx.l  d5,d6                 | add product high with carry

    dbra    d2,.first_loop        | loop over b

    move.l  d6,(a0)               | store final carry

    | Outer loop: q = 1 to len-1
    move.l  a3,a1                 | a1 = dst pointer (will be incremented)
    move.l  d0,d4                 | outer loop counter (original len-1)
    beq     .done                 | if zero, exit
    subq.l  #1,d4                 | decrement outer counter

.outer_loop:
    move.l  (a4)+,d1              | d1 = next a[q], increment a

    move.l  a2,a5                 | a5 = b pointer (autoincrement)
    addq.l  #4,a1                 | increment dst base pointer
    move.l  a1,a0                 | a0 = current dst position
    move.l  d0,d2                 | inner loop counter

    move.l  (a0),d6               | get current dst[i+q]
    moveq   #0,d7                 | clear carry
.inner_loop:
    move.l  (a5)+,d3              | d3 = b[bi], increment b
    mulu.l  d1,d5,d3              | emulate 64-bit product: d5:d3 = a[q]*b[bi]
    add.l   d7,d5                 | add carry-in (cannot overflow)

    add.l   d3,d6                 | add product low
    move.l  d6,(a0)+              | store result, increment dst
    move.l  (a0),d6               | get current dst[i+q]
    addx.l  d5,d6                 | add product high with carry
    moveq   #0,d7                 | clear carry reg
    addx.l  d7,d7                 | propagate carry

    dbra    d2,.inner_loop        | inner loop

    sub.l   (a0),d6               | adjust d6 (trash subtraction)
    move.l  d6,(a0)+              | store final result

    dbra    d4,.outer_loop        | outer loop

.done:
    movem.l (sp)+,d2-d7/a2-a5     | restore registers
.done2:
    rts                           | return

| ----------------------------------------------------------------------
| Function: square
| Inputs:
|   a0 - dst (uint32_t*)
|   a1 - src (const uint32_t*)
|   d0 - len (int)
| ----------------------------------------------------------------------

    .globl  __ZN10FastMath326squareEPjPKjs
    .globl  __ZN10FastMath326squareEPmPKms

__ZN10FastMath326squareEPjPKjs:
__ZN10FastMath326squareEPmPKms:
    movem.l d2-d7/a2-a5,-(sp)     | save registers

    move.l  a0,a2                 | to = dst
    move.l  a1,a3                 | from = src

    move.w  d0,d1                 | len in d0, copy to d1
    subq.w  #1,d1                 | d1 = len - 1
    blt     .SquareDone            | if <0 exit

.InitLoop:
    move.l  (a3)+,d2              | s = *from++
    mulu.l  d2,d3,d2              | p = (uint64_t)s*s
    move.l  d2,(a2)+              | *to++ = low
    move.l  d3,(a2)+              | *to++ = high
    dbf     d1,.InitLoop          | loop

    move.w  d0,d1                 | reset counter
    subq.w  #1,d1                 | d1 = len-1
    bmi     .SquareDone            | if <0 exit

    sub.w   #4,a0                 | --to

.DoubleLoop: .globl .DoubleLoop
    move.l  (a1)+,d3              | l = *from++
    move.l  a1,a4                 | from2 = from
    sub.l   a3,a3                 | carrylo = 0
    sub.l   a5,a5                 | carryhi = 0

    add.w   #8,a0                 | to += 2
    move.l  a0,a2                 | to2 = to

    move.w  d1,d2
    subq.w  #1,d2                 | j = i+1
    bmi     .InnerDone             | if j<0 exit

    moveq   #0,d0
.InnerLoop:
    move.l  (a4)+,d6              | load from2[j]
    mulu.l  d3,d5,d6              | m = (uint64_t)l*from2[j]
    moveq   #0,d4                 | carryhi = 0

    add.l   d6,d6                 | double low
    addx.l  d5,d5                 | double mid
    addx.l  d0,d4                 | double high

    add.l   (a2),d6               | add dst
    addx.l  d0,d5
    addx.l  d0,d4                 | propagate carry

    add.l   a3,d6                 | add carrylo
    exg     a5,d6                 | swap carryhi with low
    addx.l  d6,d5
    addx.l  d0,d4                 | propagate carry

    move.l  a5,(a2)+              | store low
    move.l  d5,a3                 | update carrylo
    move.l  d4,a5                 | update carryhi
    dbf     d2,.InnerLoop         | loop j

.PropagateCarry:
    add.l   (a2),d5
    move.l  d5,(a2)+
    move.l  d4,d5
    moveq   #0,d4
    addx.l  d0,d5
    bne     .PropagateCarry       | ripple carry

.InnerDone:
    dbf     d1,.DoubleLoop        | outer loop

.SquareDone:
    movem.l (sp)+,d2-d7/a2-a5     | restore registers
    rts                           | return
