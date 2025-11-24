# ----------------------------------------------------------------------
# edmul32.asm - 68000 assembly routine for Edwards curve multiplication (32-bit limbs)
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
#   - _edmul: multiplication routine for Edwards curve field elements (32-bit words)
#
# Notes:
#   - Uses native mulu.l (32×32->64) available on 68020+.
#   - Implements partial product accumulation, carry propagation, and final reduction (*19).
#   - Designed for Motorola 68020+ (680x0 family).
# ----------------------------------------------------------------------

.globl _edmul
_edmul:
    movem.l d2-d7/a3-a5,-(sp)     | Save registers

    moveq   #0,d6                 | High part of result = 0
    moveq   #0,d5                 | Clear carry tracker
    lea     32(a2),a3             | Store operand pointer
    moveq   #7,d4                 | Outer loop counter

.L1:
    move.l  d6,d3                 | Save previous high result
    moveq   #0,d2                 | Clear temp
    move.l  d5,d6                 | Restore carry
    moveq   #0,d7                 | Clear low result
    add.l   d3,d7                 | Add previous high to low
    addx.l  d2,d6                 | Add carry

    | Set up pointers for inner loop
    neg.l   d4
    lea     (0,a3,d4.w*4),a5      | Second operand pointer
    movea.l a1,a4                 | First operand pointer
    moveq   #0,d5                 | Clear carry

    moveq   #7,d2
    add.l   d4,d2                 | Inner loop counter
    moveq   #0,d0                 | Clear temp

.L0:
    move.l  (a4)+,d1              | Load first operand word
    mulu.l  -(a5),d3,d1           | Multiply words (d3:d1 = aj*bij)
    add.l   d1,d7                 | Add product low
    addx.l  d3,d6                 | Add product high with carry
    addx.l  d0,d5                 | Propagate carry
    dbf     d2,.L0                | Inner loop

    | Prepare for next iteration
    lea     (32,a1,d4.w*4),a5     | Adjust first operand pointer
    neg.l   d4
    move.l  a3,a4                 | Restore second operand pointer

    move.l  d4,d0
    bgt.s   .L2
    bra     .L4

.L3:
    move.l  (a5)+,d3              | Load word
    mulu.l  -(a4),d2,d3           | Multiply (d2:d3 = aj*bij)

    moveq   #0,d1
    | Multiply by 38 via shift-and-add
    add.l   d3,d3
    addx.l  d2,d2
    addx.l  d1,d1
    add.l   d3,d7
    addx.l  d2,d6
    addx.l  d1,d5

    | Repeat shifts/adds
    add.l   d3,d3
    addx.l  d2,d2
    addx.l  d1,d1
    add.l   d3,d7
    addx.l  d2,d6
    addx.l  d1,d5

    add.l   d3,d3
    addx.l  d2,d2
    addx.l  d1,d1
    add.l   d3,d3
    addx.l  d2,d2
    addx.l  d1,d1
    add.l   d3,d3
    addx.l  d2,d2
    addx.l  d1,d1
    add.l   d3,d7
    addx.l  d2,d6
    addx.l  d1,d5
.L2:
    dbf     d0,.L3

.L4:
    move.l  d7,(a0)+              | Store result word
    dbf     d4,.L1

    | Final normalization
    add.l   d7,d7
    moveq   #0,d3
    addx.l  d3,d3
    add.l   d6,d6
    move.l  d6,d4
    moveq   #0,d6
    addx.l  d6,d6
    or.l    d4,d3
    move.l  d3,d7
    move.l  d5,d2
    add.l   d5,d2
    add.l   d6,d2
    move.l  d2,d6
    or.l    d7,d2
    beq.s   .L5

    | Final adjustment *19
    move.l  d6,d2
    move.l  d7,d3
    add.l   d3,d3
    addx.l  d2,d2
    add.l   d3,d3
    addx.l  d2,d2
    add.l   d3,d3
    addx.l  d2,d2
    add.l   d7,d3
    addx.l  d6,d2
    add.l   d3,d3
    addx.l  d2,d2
    add.l   d3,d7
    addx.l  d2,d6

    sub.l   #32,a0
    bclr    #7,28(a0)

    moveq   #0,d5
    moveq   #6,d2
.L9:
    add.l   (a0),d7
    addx.l  d5,d6
    move.l  d7,(a0)+
    move.l  d6,d7
    moveq   #0,d6
    dbf     d2,.L9

    add.l   (a0),d7
    move.l  d7,(a0)

.L5:
    movem.l (sp)+,d2-d7/a3-a5     | Restore registers
    rts                           | Return
