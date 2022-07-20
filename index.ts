'use strict';

import {loadSo, unloadAllSo} from './soutils'
import {basename} from 'path'
import {InlineHooker} from './InlineHooker'
import {dumpMemory, showAsmCode, _frida_err, _frida_hexdump, _frida_log} from './fridautils'

//////////////////////////////////////////////////
// global variables 
let soname = 'libMyGame.so'

// never define callee function as a local variable, or it will be free by GC system 
const frida_fun = new NativeCallback(function(sp:NativePointer){
    console.log('sp', sp)
},'void',['pointer'])

let trampoline_len = Process.pageSize
const trampoline_ptr = Memory.alloc(trampoline_len)
const trampoline_ptr_end = trampoline_ptr.add(trampoline_len);


let test = function()
{
    let m = Process.findModuleByName(soname);
    if(m==null) return;
    //let loadm  = loadPatchSo();
    let infos:{hook_offset:number,hook_fun_ptr:NativePointer}[];

    //InlineHooker.init([soname]);

    let arch = Process.arch;
    if(arch == 'arm64'){
        infos = [
            {hook_offset:0x2dc8bc, hook_fun_ptr:frida_fun  },
        ]
    }
    else if(arch=='arm'){
        infos = [
            {hook_offset :0x1f36ed, hook_fun_ptr:frida_fun  },
        ]
    }
    else{
        throw `unhandle architecture ${arch}`
    }
    let trampoline_p = trampoline_ptr;
    infos.forEach(h=>{
        let m = Process.getModuleByName(soname)
        let hook_ptr = m.base.add(h.hook_offset);
        let hook_fun_ptr = h.hook_fun_ptr;
        if(hook_fun_ptr==undefined) throw `can not find hook_fun_ptr when handle ${JSON.stringify(h)}`
        let sz = InlineHooker.inlineHookPatch(trampoline_ptr,hook_ptr, hook_fun_ptr, ptr(h.hook_offset));
        trampoline_p = trampoline_p.add(sz)
        if(trampoline_p.compare(trampoline_ptr_end)>=0){
            throw `trampoline_ptr beyond of trampoline_ptr_end, ${trampoline_p}/${trampoline_ptr_end}`
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





