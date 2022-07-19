'use strict';

import {loadSo} from './soutils'
import {basename} from 'path'
import {InlineHooker} from './InlineHooker'
import {dumpMemory, _frida_err, _frida_hexdump, _frida_log} from './fridautils'
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
        ],)
    // console.log(JSON.stringify(loadm))
    return loadm;
}

let test = function()
{
    let m = Process.findModuleByName(soname);
    if(m==null) return;
    let loadm  = loadPatchSo();

    let trampoline_ptr = m.base.add(soinfo.loads[0].virtual_size);
    let trampoline_ptr_end = m.base.add(soinfo.loads[1].virtual_address);

    InlineHooker.init();

    let infos;
    let frida_fun = new NativeCallback(function(sp:NativePointer){
        console.log(sp.readUtf8String(),'from frida_fun')
    },'void',['pointer'])

    const cm = new CModule(`
//#include <stdio.h>
void _frida_fun(const char* s);
void fun(void) {
  //printf("Hello World from CModule\\n");
  _frida_fun("Hello World from CModule\\n");
}
`,{
    _frida_fun: frida_fun,
});

console.log(JSON.stringify(cm));

const fun = new NativeFunction(cm.fun, 'void', []);

    let arch = Process.arch;
    if(arch == 'arm64'){
        infos = [
            //{hook_ptr :m.base.add(0x2f371c), hook_fun_ptr:loadm?.syms.hook_test1 },
            //{hook_ptr :m.base.add(0x2f372c), hook_fun_ptr:loadm?.syms.hook_test1 },
            {hook_ptr :m.base.add(0x2dc868), hook_fun_ptr:loadm?.syms.hook_test1  },
        ]
    }
    else if(arch=='arm'){
        infos = [
            {hook_ptr :m.base.add(0x1f3701), hook_fun_ptr:loadm?.syms.hook_test1  },
        ]
    }
    else{
        throw `unhandle architecture ${arch}`
    }
    infos.forEach(h=>{
        let m = Process.getModuleByName(soname)
        let hook_ptr = h.hook_ptr;
        let hook_fun_ptr = h.hook_fun_ptr;
        console.log(JSON.stringify(h))
        console.log('origin code')
        dumpMemory(hook_ptr, 0x10)
        if(hook_fun_ptr==undefined) throw `can not find hook_fun_ptr when handle ${JSON.stringify(h)}`
        let sz = InlineHooker.inlineHookPatch(trampoline_ptr,hook_ptr, hook_fun_ptr, m.base);
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
        console.log('before attach', funp); dumpMemory(funp)
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
        console.log('after attach', funp); dumpMemory(funp)
    })
    // inject when then game has been started
    fun();
}

let cleanup = ()=>{
    console.log('cleanup for Typescript')
    InlineHooker.restoreAllInlineHooks()
}

rpc.exports.dispose = function(){
    cleanup();
}

console.log('########################################');
main();





