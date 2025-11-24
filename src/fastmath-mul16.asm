# ----------------------------------------------------------------------
# fastmath-mul16.asm - 68000 assembly routines
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
#   - Square routine using MUL32 macro
#   - FastMath32_mul routine (schoolbook multiplication)
#
# Notes:
#   - MUL32 macro emulates mulu.l (32×32->64) using mulu.w.
#   - Carry propagation uses addx.l to inject carries into high words.
#   - Designed for clarity, maintainability, and GPL distribution.
# ----------------------------------------------------------------------

.include "mul32.mac"
| Input parameters:
| a0: dst (pointer to uint32_t array)
| a1: a   (pointer to uint32_t array)
| a2: b   (pointer to uint32_t array)
| d0: len (number of elements, assumed > 0)
__ZN10FastMath323mulEPjPKjS2_i: .globl __ZN10FastMath323mulEPjPKjS2_i
__ZN10FastMath323mulEPmPKmS2_i: .globl __ZN10FastMath323mulEPmPKmS2_i
FastMath32_mul:
    subq.l  #1,d0                 | Adjust len once here for dbra (len-1)
    blt     .done2                | If len <= 0, exit
    movem.l d2-d7/a2-a6,-(sp)     | Save registers (d7 not needed later)

    move.l  a0,a3                 | a3 = dst base
    move.l  a1,a4                 | a4 = a pointer (autoincrement)
                                  | a2 = b base

    | First loop: i = 0 case
    move.l  (a4)+,d3              | d3 = a[0], increment a
    move.l  a2,a5                 | a5 = b pointer (autoincrement)
    moveq   #0,d6                 | carry = 0 (upper 32 bits)
    move.l  d0,d2                 | use pre-decremented counter

.first_loop:
    move.l  (a5)+,d7              | d7 = b[i], increment b
    MUL32   d3,d7,d1,d5,d4        | emulate mulu.l d3*d7 -> d1:d5

    | 64-bit addition with carry
    add.l   d5,d6                 | add product low to carry
    move.l  d6,(a0)+              | store result, increment dst
    moveq   #0,d6                 | clear for carry propagation
    addx.l  d1,d6                 | add product high with carry

    dbra    d2,.first_loop        | loop over b

    move.l  d6,(a0)               | store final carry

    | Outer loop: q = 1 to len-1
    move.l  d0,d4                 | outer loop counter (original len-1)
    beq     .done                 | if zero, exit
    subq.l  #1,d4                 | decrement outer counter

.outer_loop:
    | Set up pointers
    move.l  a2,a5                 | a5 = b pointer (autoincrement)
    addq.l  #4,a3                 | increment dst base pointer
    move.l  a3,a0                 | a0 = current dst position
    swap    d4                    | prepare inner loop counter
    move.w  d0,d4                 | inner loop counter = len

    move.l  (a4)+,d3              | d3 = next a[q], increment a

    move.l  (a0),d6               | get current dst[i+q]
    moveq   #0,d7                 | clear carry
.inner_loop:
    move.l  d4,a1                 | save counters

    move.l  (a5)+,d1              | d1 = b[bi], increment b

    MUL32   d3,d1,d2,d5,d4        | emulate mulu.l d3*d1 -> d2:d5

    add.l   d7,d2                 | add carry-in (cannot overflow)

    | Add with carry to dst[i+q]
    add.l   d5,d6                 | add product low
    move.l  d6,(a0)+              | store result, increment dst
    move.l  (a0),d6               | get current dst[i+q]
    addx.l  d2,d6                 | add product high with carry
    moveq   #0,d7                 | clear carry reg
    addx.l  d7,d7                 | propagate carry

    move.l  a1,d4                 | restore counters
    dbra    d4,.inner_loop        | inner loop

    | Store final carry with proper propagation
    sub.l   (a0),d6               | adjust d6 (trash subtraction)
    swap    d4                    | restore outer counter
    move.l  d6,(a0)+              | store final result

    dbra    d4,.outer_loop        | outer loop

.done:
    movem.l (sp)+,d2-d7/a2-a6     | restore registers
.done2:
    rts                           | return

| Function: square
| Inputs:
|   a0 - dst (uint32_t*)
|   a1 - src (const uint32_t*)
|   d0 - len (int)
	.globl	__ZN10FastMath326squareEPjPKjs
	.globl	__ZN10FastMath326squareEPmPKms
__ZN10FastMath326squareEPjPKjs:
__ZN10FastMath326squareEPmPKms:
    movem.l d2-d7/a2-a6,-(sp)        | save registers

    move.l  a0,a2                    | uint32_t *to = dst;
    move.l  a1,a3                    | uint32_t const *from = src;

    move.w  d0,d1                    | len in d0, copy to d1
    subq.w  #1,d1                    | d1 = len - 1
    blt     .SquareDone              | if (len-1 < 0) exit

.InitLoop:
    move.l  (a3)+,d4                 | uint32_t s = *from++;

    move.l  d4,d7                    | duplicate operand
    MUL32   d4,d7,d3,d2,d6           | emulate mulu.l d4*d4 -> d3:d2

    move.l  d2,(a2)+                 | *to++ = low 32 bits
    move.l  d3,(a2)+                 | *to++ = high 32 bits
    dbf     d1,.InitLoop             | loop for i = len-1..0

    move.w  d0,d1                    | reset loop counter
    subq.w  #1,d1                    | d1 = len - 1
    bmi     .SquareDone              | if (len-1 < 0) exit

    sub.w   #4,a0                    | --to (back up 4 bytes)

.DoubleLoop:
    move.l  (a1)+,a3                 | uint32_t l = *from++;
    move.l  a1,a4                    | uint32_t const *from2 = from;
    sub.l   a6,a6                    | carrylo = 0
    sub.l   a5,a5                    | carryhi = 0

    add.w   #8,a0                    | to += 2
    move.l  a0,a2                    | to2 = to

    move.w  d1,d2                    | j counter
    subq.w  #1,d2                    | j = i+1
    bmi     .InnerDone               | if j < 0 exit inner loop

    moveq   #0,d0                    | clear tmp
.InnerLoop:
    move.l  (a4)+,d7                 | load from2[j]
    move.l  a3,d4                    | operand = l

    MUL32   d4,d7,d5,d6,d0           | emulate l*d7 -> d5:d6

    moveq   #0,d4                    | carryhi = 0
    moveq   #0,d0                    | clear tmp
    add.l   d6,d6                    | double low
    addx.l  d5,d5                    | double mid
    addx.l  d0,d4                    | double high

    add.l   (a2),d6                  | add existing dst
    addx.l  d0,d5                    | propagate carry
    addx.l  d0,d4                    | propagate carry

    add.l   a6,d6                    | add carrylo
    exg     a5,d6                    | swap carryhi with low
    addx.l  d6,d5                    | add carryhi
    addx.l  d0,d4                    | propagate carry

    move.l  a5,(a2)+                 | store low
    move.l  d5,a6                    | update carrylo
    move.l  d4,a5                    | update carryhi
    dbf     d2,.InnerLoop            | loop j

.PropagateCarry:
    add.l   (a2),d5                  | add into dst
    move.l  d5,(a2)+                 | store
    move.l  d4,d5                    | shift carry
    moveq   #0,d4                    | clear
    addx.l  d0,d5                    | propagate carry
    bne     .PropagateCarry          | loop until no carry

.InnerDone:
    dbf     d1,.DoubleLoop           | loop i

.SquareDone:
    movem.l (sp)+,d2-d7/a2-a6        | restore registers
    rts                              | return
