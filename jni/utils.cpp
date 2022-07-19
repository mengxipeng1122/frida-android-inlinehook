
#include "utils.h"

char* getClassName(void* pobj)
{
    const auto* pthiz = (unsigned char*)pobj;               //LOG_INFOS("%p", pthiz);
    const auto* pftab =*(unsigned char**)&pthiz[0];         //LOG_INFOS("%p", pftab);
    const auto* p     =*(unsigned char**)&pftab[-8];        //LOG_INFOS("%p", p    );
    if(p!=NULL)
    {
        auto* s = *(char**)&p[0x08];                        //LOG_INFOS(" s %p ", s);
        return s;
    }
    return (char*)NULL;
}


#ifdef ARM64_V8A
void showRegsARM64(unsigned char* sp)
{
    // show static 
    unsigned int offset = 0;
    LOG_INFOS("x0   %p", *(void**)&sp[0xf0]);
    LOG_INFOS("x1   %p", *(void**)&sp[0xf8]);
    LOG_INFOS("x2   %p", *(void**)&sp[0xe0]);
    LOG_INFOS("x3   %p", *(void**)&sp[0xe8]);
    LOG_INFOS("x4   %p", *(void**)&sp[0xd0]);
    LOG_INFOS("x5   %p", *(void**)&sp[0xd8]);
    LOG_INFOS("x6   %p", *(void**)&sp[0xc0]);
    LOG_INFOS("x7   %p", *(void**)&sp[0xc8]);
    LOG_INFOS("x8   %p", *(void**)&sp[0xb0]);
    LOG_INFOS("x9   %p", *(void**)&sp[0xb8]);
    LOG_INFOS("x10  %p", *(void**)&sp[0xa0]);
    LOG_INFOS("x11  %p", *(void**)&sp[0xa8]);
    LOG_INFOS("x12  %p", *(void**)&sp[0x90]);
    LOG_INFOS("x13  %p", *(void**)&sp[0x98]);
    LOG_INFOS("x14  %p", *(void**)&sp[0x80]);
    LOG_INFOS("x15  %p", *(void**)&sp[0x88]);
    LOG_INFOS("x16  %p", *(void**)&sp[0x70]);
    LOG_INFOS("x17  %p", *(void**)&sp[0x78]);
    LOG_INFOS("x18  %p", *(void**)&sp[0x60]);
    LOG_INFOS("x19  %p", *(void**)&sp[0x68]);
    LOG_INFOS("x20  %p", *(void**)&sp[0x50]);
    LOG_INFOS("x21  %p", *(void**)&sp[0x58]);
    LOG_INFOS("x22  %p", *(void**)&sp[0x40]);
    LOG_INFOS("x23  %p", *(void**)&sp[0x48]);
    LOG_INFOS("x24  %p", *(void**)&sp[0x30]);
    LOG_INFOS("x25  %p", *(void**)&sp[0x38]);
    LOG_INFOS("x26  %p", *(void**)&sp[0x20]);
    LOG_INFOS("x27  %p", *(void**)&sp[0x28]);
    LOG_INFOS("x28  %p", *(void**)&sp[0x10]);
    LOG_INFOS("x29  %p", *(void**)&sp[0x18]);
    LOG_INFOS("x30  %p", *(void**)&sp[0x00]);
    LOG_INFOS("nzcv %p", *(void**)&sp[0x08]);
}
#endif

#ifdef ARMEABI_V7A  
void showRegsARM32(unsigned char* sp)
{
}
#endif
