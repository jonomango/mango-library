#include "../../include/epic/syscall_hook.h"

#include "../../include/epic/process.h"
#include "../../include/epic/shellcode.h"
#include "../../include/misc/error_codes.h"


namespace mango {
	// hooks
	void Wow64SyscallHook::hook(const Process& process, const uint32_t callback, const SetupOptions& options) {
		this->release();

		// only works for wow64 processes obviously...
		if (process.is_64bit())
			throw NotWow64Process();

		// ntdll.dll:Wow64Transition
		this->wow64_transition = uint32_t(process.get_proc_addr(
			enc_str("ntdll.dll"), enc_str("Wow64Transition")));

		// older versions of windows maybe?
		if (!this->wow64_transition)
			throw FailedToVerifyX64Transition();

		this->m_process = &process;
		this->m_options = options;

		// so we can write
		const auto protection = process.set_mem_prot(this->wow64_transition, 4, PAGE_EXECUTE_READWRITE);

		// store original address
		this->m_original = process.read<uint32_t>(this->wow64_transition);

		// build the hook stub
		this->build_shellcode(callback);

		// hook
		process.write<uint32_t>(this->wow64_transition, this->m_shellcode_addr);

		// restore old protection
		process.set_mem_prot(this->wow64_transition, 4, protection);
	}

	// unhooks
	void Wow64SyscallHook::release() {
		// not hooked
		if (!this->m_process)
			return;

		// restore to original
		const auto protection = this->m_process->set_mem_prot(this->wow64_transition, 4, PAGE_READWRITE);
		this->m_process->write<uint32_t>(this->wow64_transition, this->m_original);
		this->m_process->set_mem_prot(this->wow64_transition, 4, protection);

		// no need anymore
		Shellcode::free(*this->m_process, this->m_shellcode_addr);

		// we're all done
		this->m_process = nullptr;
	}

	// builds the function stub
	void Wow64SyscallHook::build_shellcode(const uint32_t callback) {
		this->m_shellcode_addr = uint32_t(Shellcode(
			// store the syscall index
			"\x50", // push eax

			// push arguments to our callback
			"\x68\x00\x00\x00\x00", // push 0x00000000
			"\x54", // push esp
			"\x80\x04\x24\x10", // add byte ptr [esp], 10h
			"\x50", // push eax

			// call our callback
			"\xBA", callback, // mov edx, callback
			"\xFF\xD2", // call edx
			"\x83\xC4\x08", // add esp, 0x8
			"\x5A", // pop edx

			// dont call original if returned false
			//"\xCC",
			"\x3C\x00", // cmp al, 0
			"\x0F\x85\x04\x00\x00\x00", // jne 4
			"\x89\xD0", // mov eax, edx
			"\x5A", // pop edx (for the syscall)
			Shellcode::ret(),

			// call the original
			"\x58", // pop eax (for the syscall)
			"\xBA", this->m_original, // mov edx, m_original
			"\xFF\xE2" // jmp edx
		).allocate_and_write(*this->m_process));
	}
} // namespace mango