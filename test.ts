'use strict';

import {basename} from 'path'
import {InlineHooker} from './src/InlineHooker'
import {dumpMemory, showAsmCode, _frida_err, _frida_hexdump, _frida_log} from './src/fridautils'

//////////////////////////////////////////////////
// global variables 
let soname = 'libMyGame.so'

let showARM64Regs = (sp:NativePointer)=>{
    if(Process.arch!='arm64') throw `Please check architecure, current is ${Process.arch}`
    // show static 
    console.log("dump arm64 registers value");
    console.log("x0  ", sp.add(0xf0).readPointer());
    console.log("x1  ", sp.add(0xf8).readPointer());
    console.log("x2  ", sp.add(0xe0).readPointer());
    console.log("x3  ", sp.add(0xe8).readPointer());
    console.log("x4  ", sp.add(0xd0).readPointer());
    console.log("x5  ", sp.add(0xd8).readPointer());
    console.log("x6  ", sp.add(0xc0).readPointer());
    console.log("x7  ", sp.add(0xc8).readPointer());
    console.log("x8  ", sp.add(0xb0).readPointer());
    console.log("x9  ", sp.add(0xb8).readPointer());
    console.log("x10 ", sp.add(0xa0).readPointer());
    console.log("x11 ", sp.add(0xa8).readPointer());
    console.log("x12 ", sp.add(0x90).readPointer());
    console.log("x13 ", sp.add(0x98).readPointer());
    console.log("x14 ", sp.add(0x80).readPointer());
    console.log("x15 ", sp.add(0x88).readPointer());
    console.log("x16 ", sp.add(0x70).readPointer());
    console.log("x17 ", sp.add(0x78).readPointer());
    console.log("x18 ", sp.add(0x60).readPointer());
    console.log("x19 ", sp.add(0x68).readPointer());
    console.log("x20 ", sp.add(0x50).readPointer());
    console.log("x21 ", sp.add(0x58).readPointer());
    console.log("x22 ", sp.add(0x40).readPointer());
    console.log("x23 ", sp.add(0x48).readPointer());
    console.log("x24 ", sp.add(0x30).readPointer());
    console.log("x25 ", sp.add(0x38).readPointer());
    console.log("x26 ", sp.add(0x20).readPointer());
    console.log("x27 ", sp.add(0x28).readPointer());
    console.log("x28 ", sp.add(0x10).readPointer());
    console.log("x29 ", sp.add(0x18).readPointer());
    console.log("x30 ", sp.add(0x00).readPointer());
    console.log("nzcv", sp.add(0x08).readPointer());
}

// never define callee function as a local variable, or it will be free by GC system 
const frida_fun = new NativeCallback(function(para1:NativePointer, sp:NativePointer){
    console.log('para1', para1, 'sp', sp);
    showARM64Regs(sp);
},'void',['pointer','pointer'])

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
            {hook_offset:0x2dc848, hook_fun_ptr:frida_fun  },
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
                    fun();
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
}

rpc.exports.dispose = function(){
    cleanup();
}

console.log('########################################');
main();





