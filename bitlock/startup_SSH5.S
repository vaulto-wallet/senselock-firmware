	.syntax	unified
	.arch	armv6-m
    
	.text
	.thumb
	.thumb_func
	.align	2
	.globl	Reset_Handler
Reset_Handler:
.LFB0:
	bL   __rt_initial_global_offset_table
	bl   __user_initial_stackheap
	movs r0, #0 // argc
	movs r1, #0 // argv
	bl	 main
    bl   _exit
.LFE0:
	.size Reset_Handler, . - Reset_Handler

     .text
    .align 2
    .global __rt_initial_global_offset_table
    .thumb
	.thumb_func
__rt_initial_global_offset_table:
.LFB1:
   // .text section offset
    mov  r6, pc
    subs r6, #4         // R6 = real   address of this function begin
    ldr  r0, .LFL1_1+0  // r0 = origin address of this function begin
    lsrs r0, #1         // clear bit 0
    lsls r0, #1
    subs r6, r6, r0     // r6 = .text offset(real - origin)
    
    // .data section offset
    mov  r7, r9         // r7 = r9 = __data_start__(real)
    ldr  r0, .LFL1_1+4  // r0 = __data_start__(origin)
    subs r7, r7, r0     // r7 = .data offset(real - origin)

	// reloc got item
    ldr  r4, .LFL1_1+8  // __got_start__(origin)
	adds r4, r4, r7 
    ldr  r5, .LFL1_1+12 // __got_end__(origin)
	adds r5, r5, r7
	
.LFL1_2:
    cmp  r4, r5
    bhs  .LFL1_3

    ldr  r3, [r4, #0]
    cmp  r3, #0
    beq  .LFL1_4
	
	ldr  r2, .LFL1_1 + 4  // __data_start(origin)
    cmp  r3, r2
    blo  .LFL1_5
	ldr  r2, .LFL1_1 + 16 // __bss_end__(origin)
	cmp  r3, r2
	bhs  .LFL1_5
    // got item address range in RAM    
    adds r3, r3, r7
    b    .LFL1_4
.LFL1_5:
	ldr  r2, .LFL1_1 + 20  // __executable_start(origin)
	cmp  r3, r2
	blo  .LFL1_4	
	ldr  r2, .LFL1_1 + 24  // __etext(origin)
	cmp  r3, r2
	bhs  .LFL1_4
    // got item address range in ROM
    adds r3, r3, r6

.LFL1_4: 
    str  r3, [r4, #0]
    adds r4, #4   
    b    .LFL1_2
.LFL1_3:
	bx   lr 
    .align	4 
.LFL1_1:
    .word __rt_initial_global_offset_table
    .word __data_start__ 
    .word __got_start__
    .word __got_end__
	.word __bss_end__
	.word __executable_start
	.word __etext
.LFE1:	
	.size __rt_initial_global_offset_table, .-__rt_initial_global_offset_table
	
	.text
	.align 2
	.global __user_initial_stackheap
    .thumb
	.thumb_func
 __user_initial_stackheap: 
 .LFB3:
    sub  sp, sp, #0x14
    mov  r1, sp
    add  r2, sp, #4
    str  r2, [r1, #0]
    
    movs r0, #0x16    // SYS_HEAPINFO 
    bkpt 0xab         // call semihosting
    
    ldr  r0, [sp, #0x04] // heap_base
    cmp  r0, #0
    bne  .LFL3_1
	// if heap_base equ 0 then use default
    ldr  r0, .LFL3_2+4   // __bss_end__
    ldr  r1, .LFL3_2+0   // __data_start__
    subs r0, r0, r1
    add  r0, r0, r9
	// align at 8 byte
    movs r1, #7
    adds r0, r0, r1
    bics r0, r0, r1
.LFL3_1:
    ldr  r1, [sp, #0x0c] // stack_base
    ldr  r2, [sp, #0x08] // heap_limit
    ldr  r3, [sp, #0x10] // stack_limit
    add  sp, sp, #0x14
	
	mov  sp, r1
	// save heap information
    ldr  r1, .LFL3_2 + 8  // __heap_info
    add  r1, r9
	ldr  r1, [r1, #0]
    str  r0, [r1, #0]
    str  r2, [r1, #4]
    bx   lr

    .align	4 
.LFL3_2:    
    .word __data_start__
    .word __bss_end__
	.word __heap_info(GOT) 
.LFE3:
	.size __user_initial_stackheap, .-__user_initial_stackheap
	
	.section	.text._exit,"ax",%progbits
	.align	2
	.global	_exit
	.thumb
	.thumb_func
	.type	_exit, %function
_exit:
.LFB4:
	ldr r1, .LFE4
	movs r0, #0x18 // SYS_EXIT
	bkpt #0xab     // call semihosting
	// this function not return 
	b .
    .align 4
.LFE4:
	.word  0x20026
	.size	_exit, .-_exit
 
 	.section	.data.__heap_info,"aw",%progbits
	.align	4
    .global __heap_info
	.type	__heap_info, %object
__heap_info:
	.word   __end__
	.word   __HeapLimit
	.size	__heap_info, .-__heap_info
     
 	.section	.text._sbrk,"ax",%progbits
	.align	2
	.global	_sbrk
	.code	16
	.thumb
	.thumb_func
	.type	_sbrk, %function
_sbrk:
.LFB5:
    ldr  r1, .LFL5_1    //__heap_info(GOT)
    add  r1, r9
	ldr  r1, [r1, #0]
	
    ldr  r2, [r1, #4]   // __heap_limit
    cmp  r2, #0
    bne  .LFL5_2
.LFL5_3:
    movs r0, #0
    subs r0, #1
    bx   lr 
.LFL5_2:
    ldr  r3, [r1, #0]   // __heap_base
    adds r3, r3, r0
    cmp  r3, r2
    bhs  .LFL5_3
    ldr  r0, [r1, #0]
    str  r3, [r1, #0]
    bx   lr   
    
    .align 4
.LFL5_1:
    .word __heap_info(GOT)
.LFE5_1:
	.size	_sbrk, .-_sbrk
    
    .end
	