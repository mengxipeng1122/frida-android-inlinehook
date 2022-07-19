
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
    LOG_INFOS("x30  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("nzcv %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x28  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x29  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x26  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x27  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x24  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x25  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x22  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x23  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x20  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x21  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x18  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x19  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x16  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x17  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x14  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x15  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x12  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x13  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x10  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x11  %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x8   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x9   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x6   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x7   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x4   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x5   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x2   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x3   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x0   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);
    LOG_INFOS("x1   %x:%p", offset, *(void**) &sp[offset]); offset+= sizeof(void*);

}
#endif

#ifdef ARMEABI_V7A  
void showRegsARM32(unsigned char* sp)
{
}
#endif
