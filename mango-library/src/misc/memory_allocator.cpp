#include "../../include/misc/memory_allocator.h"

#include "../../include/epic/process.h"


namespace mango {
	// allocate a block of memory
	uintptr_t MemoryAllocator::allocate(const size_t size) {
		if (this->m_alloc_blocks.empty())
			return this->allocate_new_block(size);

		// not enough free space in the current block
		const auto& block = this->m_alloc_blocks.top();
		if (this->m_current_block_use + size >= block.size)
			return this->allocate_new_block(size);

		const auto address(block.address + this->m_current_block_use);
		this->m_current_block_use += this->align_up(size, 8);
		return address;
	}

	// free all memory
	void MemoryAllocator::release() {
		while (!this->m_alloc_blocks.empty()) {
			this->m_release(this->m_alloc_blocks.top().address);
			this->m_alloc_blocks.pop();
		}
	}

	uintptr_t MemoryAllocator::allocate_new_block(const size_t size) {
		const auto aligned_size(this->align_up(size, 8));

		this->m_current_block_use = aligned_size;
		const auto block_size(this->align_up(aligned_size, this->block_alignment));

		// allocate a block of memory
		return this->m_alloc_blocks.emplace(AllocationBlock{
			.address = this->m_allocate(block_size),
			.size = block_size
		}).address;
	}

	// align value using alignment
	size_t MemoryAllocator::align_up(const size_t value, const size_t alignment) {
		if (alignment <= 1)
			return value;
		return ((value - 1) / alignment + 1) * alignment;
	}

	ProcessMemoryAllocator::ProcessMemoryAllocator(const mango::Process& process, const uint32_t protection)
		: MemoryAllocator(
			[=, &process](const size_t size) { return uintptr_t(process.alloc_virt_mem(size, protection)); },
			[&](const uintptr_t address) { process.free_virt_mem(address); }) {}
} // namespace mango