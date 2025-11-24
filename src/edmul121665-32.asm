# ----------------------------------------------------------------------
# edmul121665-32.asm - 68020 assembly routine for Edwards curve multiplication by constant 121665
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
# Function:
#   _edmul121665: multiply input by constant 121665 and reduce modulo curve prime
#
# Notes:
#   - Uses native mulu.l (32×32->64) available on 68020+.
#   - Implements multiplication by constant 121665, normalization, and final reduction (*19).
#   - Designed for Motorola 68020+ (680x0 family).
# ----------------------------------------------------------------------

.globl _edmul121665
_edmul121665:
    movem.l d2-d4,-(sp)             | Save registers we'll modify
    
    | Initialize result registers
    moveq   #0,d4                   | Clear temp
    moveq   #0,d3                   | Clear carry
    moveq   #7,d0                   | Loop counter (8 words)

.L0:    
    move.l  d3,d2                   | d2 = carry from previous iteration
    move.l  #0x1DB41,d1              | Load constant 121665
    mulu.l  (a1)+,d3,d1             | Multiply input word * 121665 -> d3:d1
    add.l   d1,d2                   | Add product low to result
    move.l  d2,(a0)+                | Store result word
    addx.l  d4,d3                   | Add carry into high part
    dbf     d0,.L0                  | Loop until counter expires

    | Final result normalization
    add.l   d2,d2                   | Shift left low
    addx.l  d3,d3                   | Shift left high with carry
    beq.s   .L5                     | Skip normalization if zero

    | Final result adjustment *19 = *1 + *2 + *16
    move.l  d3,d2                   | Start with high part (*1)
    add.l   d3,d3                   | <<1
    add.l   d3,d2                   | *3
    add.l   d3,d3                   | <<1
    add.l   d3,d3                   | <<1
    add.l   d3,d3                   | <<1
    add.l   d3,d2                   | *19

    | Store final result words
    sub.l   #32,a0                  | rewind pointer
    bclr    #7,28(a0)               | clear high bit (field reduction)

    moveq   #6,d0                   | 7 words to store
.L9:    
    add.l   (a0),d2                 | add current value
    move.l  d2,(a0)+                | store result
    moveq   #0,d2                   | clear temp
    addx.l  d2,d2                   | propagate carry
    dbeq    d0,.L9                   | loop for all words
    
    | Store final word
    add.l   (a0),d2                 | add last word
    move.l  d2,(a0)                 | store final word

.L5:
    movem.l (sp)+,d2-d4             | Restore registers
    rts                             | Return
