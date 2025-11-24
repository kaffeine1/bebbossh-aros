# ----------------------------------------------------------------------
# edsquare16.asm - 68000 assembly routine for Edwards curve squaring
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
#   - _edsquare: squaring routine for Edwards curve field elements
#
# Notes:
#   - Uses MUL32 macro to emulate 32×32->64 multiplication.
#   - Implements mixed term doubling, self terms, and special multipliers (76, 38, 19).
#   - Designed for Motorola 68000 (680x0 family).
# ----------------------------------------------------------------------

.include "mul32.mac"

_edsquare: .globl _edsquare
    movem.l d2-d7/a2-a5,-(sp)     | Save registers

    moveq   #0,d2                 | u = d2:d1 (low accumulator)
    moveq   #0,d3                 | v = d3 (high accumulator)

    move.l  d3,a5                 | Outer loop counter i = 0..7
.Outer:
    move.l  d2,d1                 | shift u
    move.l  d3,d2                 | u += (uint64_t)v << 32
    moveq   #0,d3                 | reset v

    move.l  a1,a2                 | aj = a
    move.l  a5,d4
    add.l   d4,d4
    add.l   d4,d4
    lea     4(a1,d4),a3           | bij = a + i + 1

| ---- Double add mixed terms ----
    move.l  a5,d4                 | j = (i+1)>>1
    addq.l  #1,d4
    lsr.l   #1,d4
    beq     .SkipInnerDouble

    subq.l  #1,d4
.InnerDouble:
    move.l  d4,a4                 | save inner counter
    move.l  (a2)+,d4              | load aj++
    move.l  -(a3),d7              | load --bij
    MUL32   d4,d7,d6,d5,d0        | x = aj*bij

    move.l  a4,d4                 | restore counter
    add.l   d5,d1
    addx.l  d6,d2                 | u += x
    moveq   #0,d7
    addx.l  d7,d3                 | v += carry
    add.l   d5,d1
    addx.l  d6,d2                 | u += x again (double)
    addx.l  d7,d3                 | v += carry
    dbf     d4,.InnerDouble
.SkipInnerDouble:

| ---- Single add self term ----
    move.l  a5,d0
    btst    #0,d0
    bne     .SkipSelfTerm
    move.l  (a2)+,d4
    move.l  -(a3),d7
    MUL32   d4,d7,d6,d5,d0        | x = aj*bij
    moveq   #0,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
.SkipSelfTerm:

| ---- Multiply by 76 ----
    move.l  a5,d5
    addq.l  #1,d5
    lsr.l   #1,d5
    move.l  d5,d4
    add.l   d4,d4
    add.l   d4,d4
    lea     (a2,d4),a2            | aj += (i+1)>>1
    lea     32(a1),a3             | bij = a+8

    move.l  a5,d5
    lsr.l   #1,d5
    moveq   #2,d4
    sub.l   d5,d4
    blt     .SkipInner76
.Inner76:
    move.l  d4,a4
    move.l  (a2)+,d4
    move.l  -(a3),d7
    MUL32   d4,d7,d6,d5,d0        | x = aj*bij
    move.l  a4,d4
    moveq   #0,d7

    add.l   d5,d5                 | *2
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d5                 | *4
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
    add.l   d5,d5                 | *8
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
    add.l   d5,d5                 | *16
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d5                 | *32
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d5                 | *64
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
    dbf     d4,.Inner76
.SkipInner76:

| ---- Single add self term *38 ----
    move.l  a5,d0
    btst    #0,d0
    bne     .SkipSelfTerm38
    move.l  (a2)+,d4
    move.l  -(a3),d7
    MUL32   d4,d7,d6,d5,d0        | x = aj*bij
    moveq   #0,d7
    add.l   d5,d5                 | *2
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
    add.l   d5,d5                 | *4
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
    add.l   d5,d5                 | *8
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d5                 | *16
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d5                 | *32
    addx.l  d6,d6
    addx.l  d7,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
.SkipSelfTerm38:

    move.l  d1,(a0)+              | store result limb
    addq.l  #1,a5
    cmp.w   #8,a5
    bne     .Outer

    add.l   d1,d1                 | shift left, check overflow
    addx.l  d2,d2
    addx.l  d3,d3
    move.l  d2,d1
    or.l    d3,d1
    beq     .Fine

| ---- Final adjustment *19 ----
    move.l  d2,d6
    move.l  d3,d7
    add.l   d2,d2
    addx.l  d3,d3                 | *2
    add.l   d2,d6
    addx.l  d3,d7                 | *3
    add.l   d2,d2
    addx.l  d3,d3                 | *4
    add.l   d2,d2
    addx.l  d3,d3                 | *8
    add.l   d2,d2
    addx.l  d3,d3                 | *16
    add.l   d2,d6
    addx.l  d3,d7                 | *19 adjustment complete

    sub.l   #32,a0                | rewind pointer to start of result
    bclr    #7,28(a0)             | clear high bit (field reduction)

    move    #0,d5                 | zero register for carry propagation
    moveq   #6,d0                 | loop counter = 7 words
.Add:
    add.l   (a0),d6               | add into result limb
    addx.l  d5,d7                 | propagate carry
    move.l  d6,(a0)+              | store result
    move.l  d7,d6                 | shift carry
    moveq   #0,d7                 | clear high carry
    dbf     d0,.Add               | loop

    add.l   (a0),d6               | final word add
    move.l  d6,(a0)               | store final word

.Fine:
    movem.l (sp)+,d2-d7/a2-a5     | restore registers
    rts                           | return
