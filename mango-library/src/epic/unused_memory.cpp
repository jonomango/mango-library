#include "../../include/epic/unused_memory.h"

#include "../../include/epic/process.h"

#include <algorithm>


namespace {
	// find unused memory in a process
	// return false in the predicate to skip that memory region
	// returned memory ranges are sorted, bigger->smallest
	template <typename Predicate>
	std::vector<mango::MemoryRange> find_all_unused_memory(const mango::Process& process, const size_t min_size, Predicate&& predicate) {
		std::vector<mango::MemoryRange> unused_memory;

		MEMORY_BASIC_INFORMATION mbi;
		for (const void* address = 0; VirtualQueryEx(process.get_handle(), address, &mbi, sizeof(mbi));
			*reinterpret_cast<uintptr_t*>(&address) += mbi.RegionSize) {

			// not valid
			if (!std::invoke(predicate, mbi))
				continue;

			// read the entire region
			const auto buffer = std::make_unique<uint8_t[]>(mbi.RegionSize);
			process.read(address, buffer.get(), mbi.RegionSize);

			// starting from the end, count how many null bytes
			size_t num_null_bytes = 0;
			for (; num_null_bytes < mbi.RegionSize && !buffer[mbi.RegionSize - num_null_bytes - 1]; ++num_null_bytes);

			// safety amount
			if (num_null_bytes <= 12)
				continue;

			// this is in case there happens to be a legit instruction with null bytes at the end
			num_null_bytes -= 12;

			// add it to the list
			if (num_null_bytes >= min_size)
				unused_memory.push_back({ uintptr_t(address) + (mbi.RegionSize - num_null_bytes), num_null_bytes });
		}

		// sort by biggest size
		std::sort(unused_memory.begin(), unused_memory.end(), [](const auto& first, const auto& second) {
			return first.m_size > second.m_size;
		});

		return unused_memory;
	}
} // namespace

namespace mango {
	// find unused memory (executable + readable + writeable) in a process
	// slightly misleading name since it also returns COW memory
	std::vector<MemoryRange> find_all_unused_xrw_memory(const Process& process, const size_t min_size) {
		return find_all_unused_memory(process, min_size, [](auto& mbi) {
			return mbi.Protect == PAGE_EXECUTE_READWRITE || 
				mbi.Protect == PAGE_EXECUTE_WRITECOPY;
		});
	}

	// find unused memory (executable + readable) in a process 
	std::vector<MemoryRange> find_all_unused_xr_memory(const Process& process, const size_t min_size) {
		return find_all_unused_memory(process, min_size, [](auto& mbi) {
			return mbi.Protect == PAGE_EXECUTE_READ ||
				mbi.Protect == PAGE_EXECUTE_WRITECOPY;
		});
	}

	// wrapper around find_all_unused_*_memory()
	uintptr_t find_unused_xrw_memory(const Process& process, const size_t size) {
		const auto unused_memory = find_all_unused_xrw_memory(process, size);
		if (unused_memory.empty())
			return 0;

		return unused_memory.front().m_address;
	}

	// wrapper around find_all_unused_*_memory()
	uintptr_t find_unused_xr_memory(const Process& process, const size_t size) {
		const auto unused_memory = find_all_unused_xr_memory(process, size);
		if (unused_memory.empty())
			return 0;

		return unused_memory.front().m_address;
	}
} // namespace mango