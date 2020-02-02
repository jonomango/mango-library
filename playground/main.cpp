#include "unit_tests.h"

#include <misc/logger.h>
#include <epic/process.h>
#include <epic/driver.h>


int main() {
    mango::logger.set_channels(mango::basic_colored_logging());

    run_unit_tests();

    try {
        using namespace mango;

        const auto process(Process::current());
        logger.success("Attached to process!");
    } catch (const std::exception & e) {
        mango::logger.error(e.what());
    }

    std::system("pause");
    return 0;
}