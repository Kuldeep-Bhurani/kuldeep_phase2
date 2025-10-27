	.arch armv8-a
	.file	"chall_1.c"
	.text
	.align	2
	.global	func
	.type	func, %function
func:
	sub	sp, sp, #32
	str	w0, [sp, 12] ; storing w0 on stack -> argv[1]
	mov	w0, 83 ; w0 = 83
	str	w0, [sp, 16] ; storing w0 on stack -> 83
	str	wzr, [sp, 20] ; storing wzr on stack -> 0
	mov	w0, 3 ; w0 = 3
	str	w0, [sp, 24] ; storing w0 on stack -> 3
	ldr	w0, [sp, 20] ; w0 = 0
	ldr	w1, [sp, 16] ; w1 = 83
	lsl	w0, w1, w0 ; w0 = w1 << w0 -> w0 = w1 = 83
	str	w0, [sp, 28] ; storing w0 on stack -> 83
	ldr	w1, [sp, 28] ; w1 = 83
	ldr	w0, [sp, 24] ; w0 = 3
	sdiv	w0, w1, w0 ; w0 = w1/w0 -> w0 = 27
	str	w0, [sp, 28] ; storing w0 on stack (overwriting) -> 27
	ldr	w1, [sp, 28] ; w1 = 27
	ldr	w0, [sp, 12] ; w0 = argv[1]
	sub	w0, w1, w0 ; w0 = w1 - w0 -> w0 = 27 - argv[1] 
	str	w0, [sp, 28] ; storing w0 on stack (overwriting) -> 27 - argv[1]
	ldr	w0, [sp, 28] ; w0 = 27 - argv[1] and then return is being called 
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
.LC0:
	.string	"You win!"
	.align	3
.LC1:
	.string	"You Lose :("
	.text
	.align	2
	.global	main
	.type	main, %function
main:
	stp	x29, x30, [sp, -48]! ; frame ptr, link ptr put in the stack frame
	add	x29, sp, 0
	str	w0, [x29, 28]
	str	x1, [x29, 16]
	ldr	x0, [x29, 16] ; loading into register x0 argv[0]
	add	x0, x0, 8 ; going to argv[1]
	ldr	x0, [x0] ; loading into register x0 argv[1]
	bl	atoi ; converting it to an int
	; x is the 64 bit width of 0 register and w is the 32 bit width of it
	str	w0, [x29, 44] 
	ldr	w0, [x29, 44] 
	bl	func ; calling func with w0
	cmp	w0, 0 ; compare w0 to 0
	bne	.L4 ; w0 != 0 => .L4 so to win w0 = 0
	adrp	x0, .LC0 ; triggers won
	add	x0, x0, :lo12:.LC0
	bl	puts
	b	.L6 
.L4: ; basically triggers lost
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	puts
.L6:
	nop
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
