#pragma once

#include <stdint.h>
#include <vector>


namespace mango {
	class Process;

	struct MemoryRange {
		uintptr_t m_address;
		size_t m_size;
	};

	// find unused memory (executable + readable + writeable) in a process
	// slightly misleading name since it also returns COW memory
	std::vector<MemoryRange> find_all_unused_xrw_memory(const Process& process, const size_t min_size = 0);

	// find unused memory (executable + readable) in a process 
	std::vector<MemoryRange> find_all_unused_xr_memory(const Process& process, const size_t min_size = 0);

	// wrapper around find_all_unused_*_memory()
	uintptr_t find_unused_xrw_memory(const Process& process, const size_t size);

	// wrapper around find_all_unused_*_memory()
	uintptr_t find_unused_xr_memory(const Process& process, const size_t size);
} // namespace mango