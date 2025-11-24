# ----------------------------------------------------------------------
# poly.asm - 68000 assembly routine for polynomial modular multiplication
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
#   - _addmodmul: computes (A+N)*R mod P
#
# Notes:
#   - Inputs: a0 = A (also S as output), a1 = N, a2 = R
#   - Computes S = A+N, then Z = S*R, then reduces A = Z mod P
#   - Designed for Motorola 68020 (680x0 family).
# ----------------------------------------------------------------------

.set S0,0
.set S1,4
.set S2,8
.set S3,12
.set S4,16

.set N0,0
.set N1,4
.set N2,8
.set N3,12
.set N4,16

.set R0,0
.set R1,4
.set R2,8
.set R3,12
.set R4,16

.set Z0,0
.set Z1,4
.set Z2,8
.set Z3,12
.set Z4,16
.set Z5,20

_addmodmul: .globl _addmodmul
    movem.l d2-d7/a2-a4/a6,-(sp)  | Save registers
    lea     -40(a7),a7            | Allocate stack space for Z0..Z5

| S = A+N
	move.l	S0(a0),d0	| A0
	add.l	N0(a1),d0	| S0 = A0 + N0
	move.l	S1(a0),d1	| A1
	move.l	N1(a1),d2	| N1
	addx.l	d2,d1		| S1 = A1 + N1
	move.l	S2(a0),d2	| A2
	move.l	N2(a1),d3	| N2
	addx.l	d3,d2		| S2 = A2 + N2
	move.l	S3(a0),d3	| A3
	move.l	N3(a1),d4	| N3
	addx.l	d4,d3		| S3 = A3 + N3
	move.l	S4(a0),d4	| A4
	move.l	N4(a1),d5	| N4
	addx.l	d5,d4		| S2 = A4 + N4
	| d0..d4 == S0..S4, S=A+N
	| a1 unused

	move.l	d0,S0(a0)
	move.l	d1,S1(a0)
	move.l	d2,S2(a0)
	move.l	d3,S3(a0)
	move.l	d4,S4(a0)

|	movem.l d0-d4,(a0)

| Z1Z0 = S0*R0
	move.l	d0,d5		| = S0
	mulu.l	R0(a2),d6,d5	| Z1Z0 = S0*R0
	move.l	d5,Z0(sp)	| -> Z0
	| d6 = Z1x

| Z2Z1 = Z1 + S1*R0 + S0*R1
| Z2Z1 = Z1x + Z2aZ1a + Z2bZ1b
	mulu.l	R0(a2),d5,d1  | Z2Z1 = S1*R0
	| d1 = Z1a
	| d5 = Z2a
	move.l	d0,d3		| = S0
	mulu.l	R1(a2),d4,d3	| Z2Z1 = S0*R1
	| d3 = Z1b
	| d4 = Z2b

	moveq	#0,d7 		| OVERFLOW
	moveq	#0,d2		| ZERO

	add.l	d1,d6		| Z1x + Z1a
	addx.l	d2,d7		| update overflow Z2
	add.l	d3,d6		| Z1x + Z1a + Z1b
	addx.l	d2,d7		| update overflow Z2
	move.l	d6,Z1(sp) 	| -> Z1

	| d4+d5+d7 -> Z2x
	add.l	d7,d4
	moveq	#0,d7
	addx.l	d2,d7		| d7 = overflow Z3
	add.l	d5,d4
	addx.l	d2,d7		| update overflow Z3
	| d4 = Z2x, d7=OVZ3

|Z3Z2 = OVZ3 + Z2x + S2*R0 + S1*R1 + S0*R2
	mulu.l	R2(a2),d1,d0	| Z3cZ2c = S0*R2
	move.l	S1(a0),d2
	mulu.l	R1(a2),d3,d2 | Z3bZ2b = S1*R1
	move.l	S2(a0),d5
	mulu.l	R0(a2),d6,d5	| Z3aZ2a = S2*R0

	| sum Z2
	add.l	d0,d2		| Z2b + Z2c
	moveq	#0,d0
	addx.l	d0,d7		| update overflow Z3
	add.l	d5,d2		| Z2a + Z2b + Z2c
	addx.l	d0,d7		| update overflow Z3
	add.l	d4,d2		| Zx + Z2a + Z2b + Z2c
	addx.l	d0,d7		| update overflow Z3
	move.l	d2,Z2(sp)	| -> Z2

	| d1+d3+d6+d7 -> Z3x
	add.l	d7,d1
	moveq	#0,d7
	addx.l	d0,d7		| d7 = overflow Z4
	add.l	d3,d1
	addx.l	d0,d7		| update overflow Z4
	add.l	d6,d1
	addx.l	d0,d7		| update overflow Z4
	| d1 = Z3x, d7=OVZ4

|Z4Z3 = OVZ4 + Z3x + S3*R0 + S2*R1 + S1*R2 + S0*R3
	move.l	S3(a0),d2
	mulu.l	R0(a2),d3,d2	| Z4Z3a = S3*R0
	move.l	S2(a0),d4
	mulu.l	R1(a2),d5,d4 | Z4Z3b = S2*R1
	move.l	S1(a0),d0
	mulu.l	R2(a2),d6,d0	| Z4Z3c = S1*R2
	move.l	d0,a1
	move.l	d6,a3
	move.l	S0(a0),d0
	mulu.l	R3(a2),d6,d0| Z4Z3d = S0*R3

	| sum Z3 = d1 + d2+d4+a1+d0
	add.l	d0,d2		| Z3a + Z3d
	moveq	#0,d0
	addx.l	d0,d7		| update overflow Z4
	add.l	d1,d2		| Z3x + Z3a + Z3d
	addx.l	d0,d7		| update overflow Z4
	add.l	d4,d2		| Z3x + Z3a + Z3b + Z3d
	addx.l	d0,d7		| update overflow Z4
	move.l	a1,d4
	add.l	d4,d2		| Z3x + Z3a + Z3b + Z3c + Z3d
	addx.l	d0,d7		| update overflow Z4
	move.l	d2,Z3(sp)	| -> Z3

| d3+d5+a3+d6+d7 -> Z4x
	move.l	a3,d1
	add.l	d7,d1		| a3+d7
	moveq	#0,d7
	addx.l	d0,d7		| d7 = overflow Z5
	add.l	d3,d1		| d3+a3+d7
	addx.l	d0,d7		| update overflow Z5
	add.l	d5,d1		| d3+d5+a3+d7
	addx.l	d0,d7		| update overflow Z5
	add.l	d6,d1		| d3+d5+a3+d6+d7
	addx.l	d0,d7		| update overflow Z5
	| d1 = Z4x, d7 = OVZ5

|Z5Z4 = OVZ5 + Z4x + S4*R0 + S3*R1 + S2*R2 + S1*R3 + S0*R4
	move.l	S4(a0),d2
	mulu.l	R0(a2),d3,d2	| Z5Z4a = S4*R0
	move.l	S3(a0),d4
	mulu.l	R1(a2),d5,d4 | Z5Z4b = S3*R1
	move.l	S2(a0),d0
	mulu.l	R2(a2),d6,d0	| Z5Z4c = S2*R2
	move.l	d0,a1
	move.l	d6,a3
	move.l	S1(a0),d0
	mulu.l	R3(a2),d6,d0| Z5Z4d = S1*R3
	move.l	d0,a4
	move.l	d6,a6
	move.l	S0(a0),d0
	mulu.l	R4(a2),d6,d0| Z5Z4e = S0*R4

| sum Z4 = d1 + d2+d4+a1+a4+d0
	add.l	d0,d2		| Z4a + Z4e
	moveq	#0,d0
	addx.l	d0,d7		| update overflow Z5
	add.l	d1,d2		| Z4x + Z4a + Z4e
	addx.l	d0,d7		| update overflow Z5
	add.l	d4,d2		| Z4x + Z4a + Z4b + Z4e
	addx.l	d0,d7		| update overflow Z5
	move.l	a1,d4
	add.l	d4,d2		| Z4x + Z4a + Z4b + Z4c + Z4e
	addx.l	d0,d7		| update overflow Z5
	move.l	a4,d4
	add.l	d4,d2		| Z4x + Z4a + Z4b + Z4c + Z4d + Z4e
	addx.l	d0,d7		| update overflow Z5
	move.l	d2,Z4(sp)	| -> Z4

| d3+d5+a3+a6+d6+d7 -> Z5x
	move.l	a3,d1
	add.l	d7,d1		| a3+d7
	moveq	#0,d7
	addx.l	d0,d7		| d7 = overflow Z6
	add.l	d3,d1		| d3+a3+d7
	addx.l	d0,d7		| update overflow Z6
	add.l	d5,d1		| d3+d5+a3+d7
	addx.l	d0,d7		| update overflow Z6
	add.l	d6,d1		| d3+d5+a3+d6+d7
	addx.l	d0,d7		| update overflow Z6
	move.l	a6,d6		|
	addx.l	d6,d1		| d3+d5+a3+a6+d6+d7
	addx.l	d0,d7		| update overflow Z6
	| d1 = Z5x, d7 = OVZ6

|Z6Z5 = OVZ5 + Z5x + S4*R1 + S3*R2 + S2*R3 + S1*R4
	move.l	S4(a0),d2
	mulu.l	R1(a2),d3,d2	| Z6Z5a = S4*R1
	move.l	S3(a0),d4
	mulu.l	R2(a2),d5,d4 | Z6Z5b = S3*R2
	move.l	S2(a0),d0
	mulu.l	R3(a2),d6,d0| Z6Z5c = S2*R3
	move.l	d0,a1
	move.l	d6,a3
	move.l	S1(a0),d0
	mulu.l	R4(a2),d6,d0| Z6Z5d = S1*R4

| sum Z5 = d1 + d2+d4+a1+d0
	add.l	d0,d2		| Z5a + Z5d
	moveq	#0,d0
	addx.l	d0,d7		| update overflow Z6
	add.l	d1,d2		| Z5x + Z5a + Z5d
	addx.l	d0,d7		| update overflow Z6
	add.l	d4,d2		| Z5x + Z5a + Z5b + Z5d
	addx.l	d0,d7		| update overflow Z6
	move.l	a1,d4
	add.l	d4,d2		| Z5x + Z5a + Z5b + Z5c + Z5d
	addx.l	d0,d7		| update overflow Z6
	move.l	d2,Z5(sp)	| -> Z5

| d3+d5+a3+d6+d7 -> Z6x
	move.l	a3,d1
	add.l	d7,d1		| a3+d7
	moveq	#0,d7
	addx.l	d0,d7		| d7 = overflow Z7
	add.l	d3,d1		| d3+a3+d7
	addx.l	d0,d7		| update overflow Z7
	add.l	d5,d1		| d3+d5+a3+d7
	addx.l	d0,d7		| update overflow Z7
	add.l	d6,d1		| d3+d5+a3+d6+d7
	addx.l	d0,d7		| update overflow Z7
	| d1 = Z6x, d7 = OVZ7

|Z7Z6 = OVZ7 + Z6x + S4*R2 + S3*R3 + S2*R4
	move.l	S4(a0),d2
	mulu.l	R2(a2),d3,d2 | Z7Z6a = S4*R2
	move.l	S3(a0),d4
	mulu.l	R3(a2),d5,d4 | Z7Z6b = S3*R3
	move.l	S2(a0),d0
	mulu.l	R4(a2),d6,d0 | Z7Z6c = S2*R4

| sum Z6 = d1 + d2+d4+d0
	add.l	d0,d2		| Z6a + Z6c
	moveq	#0,d0
	addx.l	d0,d7		| update overflow Z7
	add.l	d1,d2		| Z6x + Z6a + Z6c
	addx.l	d0,d7		| update overflow Z7
	add.l	d4,d2		| Z6x + Z6a + Z6b + Z6c
	addx.l	d0,d7		| update overflow Z7
	move.l	d2,a6	| -> Z6

| d3+d5+d6+d7 -> Z7x
	add.l	d7,d6		| d6+d7
	moveq	#0,d7
	addx.l	d0,d7		| d7 = overflow Z8
	add.l	d5,d6		| d5+d6+d7
	addx.l	d0,d7		| update overflow Z8
	add.l	d3,d6		| d3+d5+d6+d7
	addx.l	d0,d7		| update overflow Z8
	| d6 = Z7x, d7 = OVZ8

|Z8Z7 = OVZ8 + Z7x + S4*R3 + S3*R4
	move.l	S4(a0),d2
	mulu.l	R3(a2),d3,d2 | Z8Z7a = S4*R3
	move.l	S3(a0),d4
	mulu.l	R4(a2),d5,d4 | Z7Z7b = S3*R4

| sum Z8 = d6 + d2+d4
	add.l	d6,d2		| Z7x + Z7A
	addx.l	d0,d7		| update overflow Z8
	add.l	d4,d2		| Z67 + Z7a + Z7b
	addx.l	d0,d7		| update overflow Z8
	move.l	d2,a1	| -> Z7

| d3+d5+d7 -> Z8x
	add.l	d7,d5		| d5+d7
	add.l	d3,d5		| d3+d5+d6+d7
	| d5 = Z8x, no overflow

|Z8 = Z8x + S4*R4
	move.l	S4(a0),d2
	mulu.l	R4(a2),d2	| Z8 = S4*R4
	add.l	d2,d5		| Z8 = Z8x + S4*R4
	move.l	d5,a4

| mask and mul 5
	moveq	#3,d6
	move.l	Z4(sp),d0
	move.l	d0,d1
	and.l	d6,d0		| & 3
	move.l	d0,Z4(sp)	| Z0..Z4 == number

	sub.l	d0,d1
	move.l	d1,d0		| copy of clamped Z4

	move.l	Z5(sp),d2
	move.l	a6,d3
	move.l	a1,d4	| Z4..Z8 == d1..d5

	| shift right 2
	lsr.l	#1,d5
	roxr.l	#1,d4
	roxr.l	#1,d3
	roxr.l	#1,d2
	roxr.l	#1,d1
	lsr.l	#1,d5
	roxr.l	#1,d4
	roxr.l	#1,d3
	roxr.l	#1,d2
	roxr.l	#1,d1

	| add original -> yield *5
	add.l	d0,d1
	move.l	Z5(sp),d0
	addx.l	d0,d2
	move.l	a6,d0
	addx.l	d0,d3
	move.l	a1,d0
	addx.l	d0,d4
	move.l	a4,d0
	addx.l	d0,d5
	| *5 in d1..d5

	| add Z
	add.l	Z0(a7),d1
	move.l	Z1(a7),d0
	addx.l	d0,d2
	move.l	Z2(a7),d0
	addx.l	d0,d3
	move.l	Z3(a7),d0
	addx.l	d0,d4
	move.l	Z4(a7),d0
	addx.l	d0,d5

	moveq #-1,d7	| 0xffffffff
	|| result in d1..d5, compare gt 0x3 0xffffffff 0xffffffff xffffffff xfffffffb
	cmp.l d5,d6		| #3
	bhi.s __Done
	blo.s __Sub

	cmp.l d4,d7		| 0xffffffff
	bne.s __Done
	cmp.l d3,d7		| 0xffffffff
	bne.s __Done
	cmp.l d2,d7		| 0xffffffff
	bne.s __Done
	moveq #-5,d0	| 0xfffffffb
	cmp.l d1,d0
	bhi.s __Done
__Sub:
	moveq	#-5,d0
	sub.l	d0,d1
	subx.l	d7,d2
	subx.l	d7,d3
	subx.l	d7,d4
	subx.l	d6,d5
__Done:
	move.l	d1,S0(a0)
	move.l	d2,S1(a0)
	move.l	d3,S2(a0)
	move.l	d4,S3(a0)
	move.l	d5,S4(a0)

    lea     40(a7),a7             | release stack space
    movem.l (sp)+,d2-d7/a2-a4/a6  | restore registers
    rts                           | return
