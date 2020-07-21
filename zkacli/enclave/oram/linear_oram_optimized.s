.globl linear_oram_read_256bit_element
.section .text
linear_oram_read_256bit_element:
	# rax = 32 * rdi->element_count
	mov				0x40(%rdi), %rax
	shl				$0x5, %rax
	
	# rcx =  -(32 * rdi->element_count)
	mov				%rax, %rcx
	neg				%rcx
	
	# rax = rdi->buffer + 32 * rdi->element_count
	add				0x48(%rdi), %rax
		
	# Mitigate LVI (CVE-2020-0551)
	lfence
	
	# ymm0 = token
	# ymm1 = vector of currect index
	# ymm2 = mask (-1 if ymm3 == ymm1,  0 otherwise)
	# ymm3 = vector of selected index (rsi)
	# ymm4 = -1
	
	# Initialize token to 0
	vpxor			%xmm0, %xmm0, %xmm0
	
	# Initialize current index to 0
	vpxor			%xmm1, %xmm1, %xmm1
	
	# Create a vector full of the index of the token which was selected
	vmovq			%rsi, %xmm3
	vpbroadcastq	%xmm3, %ymm3
	
	# Initialize -1 constant
	vpcmpeqq		%ymm4, %ymm4, %ymm4

.Llinear_oram_256bit_select_loop:
		# Set mask (ymm2) to all 1 or all 0 if the current index is or isn't the selected one respectively
		vpxor 		%ymm1, %ymm3, %ymm2
		vpaddq		%ymm2, %ymm4, %ymm2
		vpshufd		$0x55, %ymm2, %ymm2
		
		# Bitwise AND the mask with the current token
		vpand		(%rax, %rcx), %ymm2, %ymm2
		vpor		%ymm2, %ymm0, %ymm0
		
		# Increment index (by subtracting -1)
		vpsubq		%ymm4, %ymm1, %ymm1
		
		# Calculate address of next token and break out of the loop if it's invalid
		add			$0x20, %rcx
		jnz			.Llinear_oram_256bit_select_loop
	
	# Store token
	vmovdqu			%ymm0, (%rdx)
	
	# Remove any trace of the token in registers
	vpxor			%xmm0, %xmm0, %xmm0
	vpxor			%xmm2, %xmm2, %xmm2
	
	# Return 1
	mov				$0x1, %eax
	
	# Mitigate LVI (CVE-2020-0551)
	pop				%rcx
	lfence
	jmp				*%rcx
