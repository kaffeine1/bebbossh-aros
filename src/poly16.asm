# ----------------------------------------------------------------------
# poly16.asm - 68000 assembly routine for polynomial reduction mod P (16-bit limbs)
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
#   - _mod5: reduce Z = S*R modulo polynomial P
#
# Notes:
#   - Operates on 9 words (Z0..Z8) stored at a0.
#   - Implements reduction by masking, multiplying by 5, and conditional subtraction.
#   - Designed for Motorola 68000 (680x0 family).
# ----------------------------------------------------------------------

| Z = S*R   ->  A = Z mod P
.set Z0,0
.set Z1,4
.set Z2,8
.set Z3,12
.set Z4,16
.set Z5,20
.set Z6,24
.set Z7,28
.set Z8,32

| a0 -> Z0...Z8
_mod5: .globl _mod5
    movem.l d2-d7/a2-a4,-(sp)     | Save registers

    lea     Z4(a0),a1             | Point to Z4

| ---- Mask and multiply by 5 ----
    moveq   #3,d6
    move.l  (a1)+,d0              | Load Z4
    move.l  d0,d1
    and.l   d6,d0                 | Z4 & 3
    move.l  d0,a4                 | Save masked value
    sub.l   d0,d1                 | d1 = Z4 - (Z4&3)

    move.l  (a1)+,d2              | Z5
    move.l  (a1)+,d3              | Z6
    move.l  (a1)+,d4              | Z7
    move.l  (a1),d5               | Z8

    move.l  d1,d0                 | Copy Z4..Z8
    move.l  d2,d6
    move.l  d3,d7
    move.l  d4,a1
    move.l  d5,a2

    | Shift right by 2 (divide by 4)
    lsr.l   #1,d5
    roxr.l  #1,d4
    roxr.l  #1,d3
    roxr.l  #1,d2
    roxr.l  #1,d1
    lsr.l   #1,d5
    roxr.l  #1,d4
    roxr.l  #1,d3
    roxr.l  #1,d2
    roxr.l  #1,d1

    | Add original -> yield *5
    add.l   d0,d1
    addx.l  d6,d2
    addx.l  d7,d3
    move.l  a1,d0
    addx.l  d0,d4
    move.l  a2,d0
    addx.l  d0,d5
    | Result *5 in d1..d5

| ---- Add Z ----
    move.l  a0,a1
    add.l   (a1)+,d1              | Add Z0
    move.l  (a1)+,d0
    addx.l  d0,d2                 | Add Z1
    move.l  (a1)+,d0
    addx.l  d0,d3                 | Add Z2
    move.l  (a1),d0
    addx.l  d0,d4                 | Add Z3
    move.l  a4,d0
    addx.l  d0,d5                 | Add masked Z4

| ---- Conditional subtraction ----
    moveq   #-1,d7                | 0xffffffff
    moveq   #3,d6
    cmp.l   d5,d6                 | Compare high limb with 3
    bhi.s   __Done
    blo.s   __Sub

    cmp.l   d4,d7                 | Check if all higher limbs are max
    bne.s   __Done
    cmp.l   d3,d7
    bne.s   __Done
    cmp.l   d2,d7
    bne.s   __Done
    moveq   #-5,d0                | 0xfffffffb
    cmp.l   d1,d0
    bhi.s   __Done

__Sub:
    moveq   #-5,d0
    sub.l   d0,d1
    subx.l  d7,d2
    subx.l  d7,d3
    subx.l  d7,d4
    subx.l  d6,d5

__Done:
    move.l  d1,(a0)+              | Store reduced result
    move.l  d2,(a0)+
    move.l  d3,(a0)+
    move.l  d4,(a0)+
    move.l  d5,(a0)

    movem.l (sp)+,d2-d7/a2-a4     | Restore registers
    rts                           | Return
