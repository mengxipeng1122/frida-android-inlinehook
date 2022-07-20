'use strict';

import {loadSo, unloadAllSo} from './soutils'
import {basename} from 'path'
import {InlineHooker} from './InlineHooker'
import {dumpMemory, showAsmCode, _frida_err, _frida_hexdump, _frida_log} from './fridautils'
import {info as patchsoinfo} from './patchso'
import {info as soinfo} from './so'

//////////////////////////////////////////////////
// global variables 
let soname = 'libMyGame.so'

let loadPatchSo = ()=>{
    let loadm = loadSo(patchsoinfo,
        {
            _frida_log:     _frida_log,
            _frida_err:     _frida_err,
            _frida_hexdump: _frida_hexdump,
        },
        [
            '__google_potentially_blocking_region_begin',
            '__google_potentially_blocking_region_end',
        ],
        [
            soname
        ],
    )
    // console.log(JSON.stringify(loadm))
    return loadm;
}

// never define callee function as a local variable, or it will be free by GC system 
export     let infos:{hook_offset:number,hook_fun_ptr:NativePointer}[];
export    let frida_fun = new NativeCallback(function(sp:NativePointer){
        //console.log(sp.readUtf8String(),'from frida_fun')
        dumpMemory(sp)
    },'void',['pointer'])

export    const cm = new CModule(`
void _frida_fun(const char* s);
void fun(void) {
    _frida_fun("Hello World from CModule\\n");
}
    `,{
        _frida_fun: frida_fun,
    });

let test = function()
{
    let m = Process.findModuleByName(soname);
    if(m==null) return;
    let loadm  = loadPatchSo();

    let trampoline_ptr = m.base.add(soinfo.loads[0].virtual_size);
    let trampoline_ptr_end = m.base.add(soinfo.loads[1].virtual_address);

    InlineHooker.init([soname]);

    const fun = new NativeFunction(cm.fun, 'void', []);
    console.log('fun', fun);
    console.log('frida_fun', frida_fun);
    fun();
    Memory.protect(fun,Process.pageSize,'rwx')
    {
        let p = fun;;
        console.log('cm', JSON.stringify(cm))
        showAsmCode(p)
        dumpMemory(p, 0x20)
    }

    let arch = Process.arch;
    if(arch == 'arm64'){
        infos = [
            //{hook_offset:0x2dc854, hook_fun_ptr:loadm?.syms.hook_test1  },
            {hook_offset:0x2dc854, hook_fun_ptr:fun  },
            // {hook_offset:0x2dc868, hook_fun_ptr:loadm?.syms.hook_test1  },
            // {hook_offset:0x2dc880, hook_fun_ptr:loadm?.syms.hook_test1  },
            // {hook_offset:0x2dc838, hook_fun_ptr:loadm?.syms.hook_test1  },
            // {hook_offset:0x2dc88c, hook_fun_ptr:loadm?.syms.hook_test1  },
        ]
    }
    else if(arch=='arm'){
        infos = [
            //{hook_offset :0x1f36f9, hook_fun_ptr:loadm?.syms.hook_test1  },
            //{hook_offset :0x1f3707, hook_fun_ptr:loadm?.syms.hook_test1  },
            //{hook_offset :0x1f372f, hook_fun_ptr:loadm?.syms.hook_test1  },
            {hook_offset :0x1f36ed, hook_fun_ptr:frida_fun  },
        ]
    }
    else{
        throw `unhandle architecture ${arch}`
    }
    infos.forEach(h=>{
        let m = Process.getModuleByName(soname)
        let hook_ptr = m.base.add(h.hook_offset);
        let hook_fun_ptr = h.hook_fun_ptr;
        console.log(JSON.stringify(h))
        console.log('origin code')
        dumpMemory(hook_ptr, 0x10)
        if(hook_fun_ptr==undefined) throw `can not find hook_fun_ptr when handle ${JSON.stringify(h)}`
        let sz = InlineHooker.inlineHookPatch(trampoline_ptr,hook_ptr, hook_fun_ptr, ptr(h.hook_offset));
        trampoline_ptr = trampoline_ptr.add(sz)
        if(trampoline_ptr.compare(trampoline_ptr_end)>=0){
            throw `trampoline_ptr beyond of trampoline_ptr_end, ${trampoline_ptr}/${trampoline_ptr_end}`
        }
    });
}


let main = ()=>{
    let fun = test;
    // early inject 
    let funs = ['dlopen', 'android_dlopen_ext']
    funs.forEach(f=>{
        let funp = Module.getExportByName(null,f);
        Interceptor.attach(funp,{
            onEnter:function(args){
                let loadpath = args[0].readUtf8String();
                if(loadpath!=null) this.name = basename(loadpath);
            },
            onLeave:function(retval){
                // soname have loaded at this moment 
                if(this.name == soname){
                    let funname = '_ZN9GameScene4initEv'; //GameScene::init(void)
                    Interceptor.attach(Module.getExportByName(soname, funname),{
                        onLeave:function(retval){
                            fun(); // inject our code after invoked GameScene::init 
                        },
                    })
                }
            },
        });
    })
    // inject when then game has been started
    fun();
}

let cleanup = ()=>{
    console.log('cleanup for Typescript')
    InlineHooker.restoreAllInlineHooks()
    unloadAllSo();
}

rpc.exports.dispose = function(){
    cleanup();
}

console.log('########################################');
main();





