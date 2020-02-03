#include "unit_tests.h"

#include <misc/logger.h>
#include <epic/process.h>

#include <epic/memory_scanner.h>
#include <epic/shellcode.h>


int main() {
    mango::logger.set_channels(mango::basic_colored_logging());

    run_unit_tests();

    try {
        using namespace mango;

        const auto process(Process::current());
        logger.success("Attached to process!");

        static constexpr auto bytes = shw::absjmp<false>(0x69);
        for (const auto result : memscn::find(process, { bytes.data(), bytes.size() }, memscn::range_all, memscn::code_filter)) {
            logger.success("0x", std::hex, std::uppercase, result);
        }
    } catch (const std::exception & e) {
        mango::logger.error(e.what());
    }

    std::system("pause");
    return 0;
}