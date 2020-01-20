#pragma once

#include <functional>
#include <stack>


namespace mango {
	class Process;

	// NOTE: this is NOT fast or optimized, this is just meant to be 
	// a quick and dirty way to avoid allocating tons of memory pages
	// when you only actually use a little
	class MemoryAllocator {
	public:
		template <typename Allocate, typename Release>
		MemoryAllocator(Allocate&& allocate, Release&& release)
			: m_allocate(std::forward<Allocate>(allocate)),
			  m_release(std::forward<Release>(release)) {}

		// allocate a block of memory
		uintptr_t allocate(const size_t size);

		// free all memory
		void release();

	private:
		uintptr_t allocate_new_block(const size_t size);

		static size_t align_up(const size_t size, const size_t alignment);

	private:
		struct AllocationBlock {
			uintptr_t address;
			size_t size;
		};

		static constexpr size_t block_alignment = 0x1000;

	private:
		std::function<uintptr_t(size_t size)> m_allocate;
		std::function<void(uintptr_t address)> m_release;
		std::stack<AllocationBlock> m_alloc_blocks;
		size_t m_current_block_use = 0;
	};

	// allocates RWX memory from a process
	class ProcessMemoryAllocator : public MemoryAllocator {
	public:
		explicit ProcessMemoryAllocator(const mango::Process& process, 
			const uint32_t protection = 0x40 /* PAGE_EXECUTE_READWRITE */);
	};
} // mango