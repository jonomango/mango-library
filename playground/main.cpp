#include "unit_tests.h"

#include <misc/logger.h>
#include <epic/process.h>
#include <epic/thread.h>
#include <epic/hardware_breakpoint.h>

#include <epic/memory_scanner.h>
#include <epic/shellcode.h>

#include <chrono>


// TODO: use only one template thing for cross-architecture stuff: eg is64bit or Ptr

// add function to get parent process id in mango::Process class

int main() {
    mango::logger.set_channels(mango::basic_colored_logging());

    //run_unit_tests();

    try {
        using namespace mango;

        const auto process(Process::current());
        logger.success("Attached to process!");

        for (const auto threadid : process.get_threadids()) {
            const Thread thread(threadid);
            logger.success("Opened thread: ", thread.get_tid());

            logger.info("Start address: 0x", std::hex, std::uppercase, 
                thread.get_start_address(process.is_64bit()));
            
            char timebuffer[256]; tm localtime;
            time_t time = thread.get_creation_time() / 1000;
            localtime_s(&localtime, &time);
            asctime_s(timebuffer, &localtime);
            logger.info("Creation time: ", timebuffer);
        }
    } catch (const std::exception& e) {
        mango::logger.error(e.what());
    }

    std::system("pause");
    return 0;
}