# ----------------------------------------------------------------------
# edsquare32.asm - 68000 assembly routine for Edwards curve squaring (32-bit limbs)
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
#   - _edsquare: squaring routine for Edwards curve field elements (32-bit words)
#
# Notes:
#   - Uses native mulu.l (32×3->64) available on 68020+.
#   - Implements mixed term doubling, self terms, and special multipliers (76, 38, 19).
#   - Designed for Motorola 68020+ (680x0 family).
# ----------------------------------------------------------------------

_edsquare: .globl _edsquare
    movem.l d2-d7/a2-a3,-(sp)     | Save registers

    moveq   #0,d2                 | u = d2:d1 (low accumulator)
    moveq   #0,d3                 | v = d3 (high accumulator)

    moveq   #0,d0                 | outer loop counter i = 0..7
.Outer:
    move.l  d2,d1                 | shift u
    move.l  d3,d2                 | u += (uint64_t)v << 32
    moveq   #0,d3                 | reset v

    move.l  a1,a2                 | aj = a
    lea     4(a1,d0.l*4),a3       | bij = a + i + 1

| ---- Double add mixed terms ----
    move.l  d0,d4
    addq.l  #1,d4
    lsr.l   #1,d4                 | j = (i+1)>>1
    beq     .SkipInnerDouble

    moveq   #0,d7
    subq.l  #1,d4
.InnerDouble:
    move.l  (a2)+,d5              | load aj++
    mulu.l  -(a3),d6,d5           | x = aj*bij
    add.l   d5,d1
    addx.l  d6,d2                 | u += x
    addx.l  d7,d3                 | v += carry
    add.l   d5,d1
    addx.l  d6,d2                 | u += x again (double)
    addx.l  d7,d3                 | v += carry
    dbf     d4,.InnerDouble
.SkipInnerDouble:

| ---- Single add self term ----
    btst    #0,d0
    bne     .SkipSelfTerm
    move.l  (a2)+,d5
    mulu.l  -(a3),d6,d5           | x = aj*bij
    moveq   #0,d7
    add.l   d5,d1
    addx.l  d6,d2
    addx.l  d7,d3
.SkipSelfTerm:

| ---- Multiply by 76 ----
    move.l  d0,d5
    addq.l  #1,d5
    lsr.l   #1,d5
    lea     (a2,d5.l*4),a2        | aj += (i+1)>>1
    lea     32(a1),a3             | bij = a+8

    move.l  d0,d5
    lsr.l   #1,d5
    moveq   #2,d4
    sub.l   d5,d4
    blt     .SkipInner76
.Inner76:
    move.l  (a2)+,d5
    mulu.l  -(a3),d6,d5           | x = aj*bij
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
    btst    #0,d0
    bne     .SkipSelfTerm38
    move.l  (a2)+,d5
    mulu.l  -(a3),d6,d5           | x = aj*bij
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
    addq.l  #1,d0
    btst    #3,d0
    beq     .Outer

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
    addx.l  d3,d7                 | *19

    sub.l   #32,a0
    bclr    #7,28(a0)             | clear high bit

    move    #0,d5
    moveq   #6,d0
.Add:
    add.l   (a0),d6
    addx.l  d5,d7
    move.l  d6,(a0)+
    move.l  d7,d6
    moveq   #0,d7
    dbf     d0,.Add

    add.l   (a0),d6               | final word add
    move.l  d6,(a0)               | store final word

.Fine:
	movem.l (sp)+,d2-d7/a2-a3
	rts
