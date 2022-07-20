

#include <map>
#include <queue>
#include <string>
#include "utils.h"

extern "C" void hook_test(unsigned char* baseaddress, unsigned char* sp)
{
    LOG_INFOS(" baseaddress %p ", baseaddress);
}
extern "C" void hook_test1(unsigned char* baseaddress, unsigned char* sp)
{
    LOG_INFOS(" baseaddress %p ", baseaddress);
#ifdef ARM64_V8A
//    showRegsARM64(sp);
#elif defined(ARMEABI_V7A )
    showRegsARM32(sp);
#else
//TODO
#error "please implements other atchitecture"
#endif
}
