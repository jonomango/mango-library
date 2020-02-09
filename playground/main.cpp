#include "unit_tests.h"

#include <misc/logger.h>
#include <epic/process.h>
#include <epic/thread.h>
#include <epic/hardware_breakpoint.h>
#include <epic/loader.h>

#include <epic/memory_scanner.h>
#include <epic/shellcode.h>

#include <misc/fnv_hash.h>

#include <chrono>


// TODO: use only one template thing for cross-architecture stuff: eg is64bit or Ptr

// TODO: add function to get parent process id in mango::Process class

int main() {
    mango::logger.set_channels(mango::basic_colored_logging());

    run_unit_tests();

    try {
        using namespace mango;

        const auto process(Process::current());
        logger.success("Attached to process!");

        const auto str = "hello world!";
        switch (Fnv1a(str)) {
        case Fnv1a("frog"):
            break;
        }

        mango::manual_map(process, "frog");
    } catch (const std::exception& e) {
        mango::logger.error(e.what());
    }

    std::system("pause");
    return 0;
}