.code

_syscall proc
	mov r10, rcx ; store rcx in r10 register
	mov eax, [rsp + 20h + 8] ; store the syscall index in eax
	pop r11 ; pop the return address into r11
	mov [rsp], r11 ; overwrite the

	syscall

	jmp qword ptr [rsp]
_syscall endp

end