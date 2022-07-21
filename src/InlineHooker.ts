
'use strict';

import {loadSo, LoadSoInfoType } from './soutils'
import { showAsmCode, dumpMemory, getPyCodeFromMemory,_frida_err, _frida_hexdump, _frida_log, readMemoryArrayBuffer } from "./fridautils";
//import {info as shadowhooksoinfo} from './shadowhookso'
import {sh_a64_rewrite} from './sh_a64'

const using_frida_for_reloc_code:boolean = true;

export abstract class InlineHooker
{
    hook_fun_ptr        : NativePointer;
    trampoline_ptr      : NativePointer;
    hook_ptr            : NativePointer;
    para1               : NativePointer;
    constructor(hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer){
        this.hook_ptr       = hook_ptr;
        this.trampoline_ptr = trampoline_ptr;
        this.hook_fun_ptr   = hook_fun_ptr;
        this.para1          = para1;
    }

    static max_code_cnt= 5;
    static max_trampoline_len = 0x200;

    putPrecode(p:NativePointer):number {
        throw `please implement putPrecode function ${JSON.stringify(this)}`
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        throw `please implement relocCode function ${JSON.stringify(this)}`
    }

    relocCodeByFrida(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        throw `please implement relocCodeByFrida function ${JSON.stringify(this)}`
    }

    putJumpCode(from:NativePointer, to:NativePointer):number {
        throw `please implement putJumpCode function ${JSON.stringify(this)}`
    }

    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        throw `please implement canBranchDirectlyBetween function ${JSON.stringify(this)}`
    }

    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        throw `please implement getJumpInstLen function ${JSON.stringify(this)}`
    }

    run():[number, ArrayBuffer]{
        let origin_bytes:ArrayBuffer=new ArrayBuffer(0)
        let offset = 0;
        let relocsz=0;
        let trampolineCodeAddr = ptr(0);
        // write trampoline code 
        Memory.patchCode(this.trampoline_ptr, InlineHooker.max_trampoline_len, code=>{
            let sz;
            // write hook_fun_ptr
            code.add(offset).writePointer(this.hook_fun_ptr); offset += Process.pointerSize;
            // write arg1
            code.add(offset).writePointer(this.para1); offset += Process.pointerSize;
            // write precode
            trampolineCodeAddr = code.add(offset);
            sz = this.putPrecode(code.add(offset)); offset += sz;
            // relocate code 
            relocsz = this.getJumpInstLen(this.hook_ptr, trampolineCodeAddr);
            if(using_frida_for_reloc_code) [sz, origin_bytes] = this.relocCodeByFrida(this.hook_ptr, code.add(offset), relocsz);
            else [sz, origin_bytes] = this.relocCode(this.hook_ptr, code.add(offset), relocsz);
            offset += sz;
            // write jump back code 
            let origin_inst_len = origin_bytes.byteLength;
            sz = this.putJumpCode(code.add(offset), this.hook_ptr.add(origin_inst_len)); offset += sz;
        });  
        // write jump code at hook_ptr
        let jumpsz = this.getJumpInstLen(this.hook_ptr, trampolineCodeAddr);
        let bs = this.hook_ptr.readByteArray(jumpsz);
        if(bs==null) throw `can not read byte at ${this.hook_ptr}`
        origin_bytes = bs;
        Memory.patchCode(this.hook_ptr, jumpsz, code=>{
            let sz = this.putJumpCode(code, trampolineCodeAddr)
        })
        return [offset, origin_bytes];
    }

    static loadm : LoadSoInfoType;  
    //static loadShaderHookSo = (loadedlibs?:string[])=>{
    //    let libs:string[] = [];
    //    if (loadedlibs!=undefined){
    //        loadedlibs.forEach(lib=>{
    //            libs.push(lib)
    //        })
    //    }
    //    let loadm = loadSo(shadowhooksoinfo,
    //        {
    //            _frida_log:     _frida_log,
    //            _frida_err:     _frida_err,
    //            _frida_hexdump: _frida_hexdump,
    //        },
    //        [
    //            '__google_potentially_blocking_region_begin',
    //            '__google_potentially_blocking_region_end',
    //        ],
    //        libs,
    //        )
    //    InlineHooker.loadm = loadm;
    //}

    //static init = (loadedlibs?:string[])=>{
    //    InlineHooker.loadShaderHookSo(loadedlibs);
    //}


    static all_inline_hooks:{[key:string]:{
            origin_bytes:ArrayBuffer| null,
            hook_ptr:NativePointer,
    }}= { };

    static hasHooked = (hook_ptr:NativePointer):boolean=>{
        return hook_ptr.toString() in InlineHooker.all_inline_hooks;
    }

    static restoreAllInlineHooks=()=>{
        let hooks = InlineHooker.all_inline_hooks;
        Object.keys(hooks)
            .forEach(k=>{
                let v = hooks[k]
                if (v.origin_bytes!=null){
                    let bs = v.origin_bytes;
                    let p = v.hook_ptr;
                    let sz = bs.byteLength;
                    Memory.patchCode(p,sz, code=>{
                        const writer = new Arm64Writer(code)
                        writer.putBytes(bs)
                        writer.flush()
                    })
                }
            })
    }

    static inlineHookerFactory(hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1: NativePointer){
        let arch = Process.arch;
        if(arch == 'arm') {
            if(hook_ptr.and(1).equals(1)){
                return new ThumbInlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
            }
            else {
                return new ArmInlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
            }
        }
        else if(arch == 'arm64'){
            return new Arm64InlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
        }
        else{
            throw `unhandle architecture ${arch}`
        }
    }

    static inlineHookPatch(trampoline_ptr:NativePointer, hook_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer):number
    {
        if(InlineHooker.hasHooked(hook_ptr)) {
            console.log(hook_ptr,'has hooked ,do not rehook')
            return 0;
        }
    
        let inlineHooker = InlineHooker.inlineHookerFactory(hook_ptr, trampoline_ptr, hook_fun_ptr, para1);
        let [trampoline_len, origin_bytes] = inlineHooker.run();
        let k = hook_ptr.toString();
        InlineHooker.all_inline_hooks[k]= {
            hook_ptr: hook_ptr,
            origin_bytes : origin_bytes,
        }
        return trampoline_len;
    }

}

class ThumbInlineHooker extends InlineHooker{

    constructor(hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer){
        super(hook_ptr.and(~1), trampoline_ptr, hook_fun_ptr,para1)
    }

    putPrecode(p:NativePointer):number {
        const writer = new ThumbWriter(p);
        writer.putPushRegs([ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', ])
        writer.putPushRegs(['r8', 'sb', 'sl', 'fp', 'ip', 'lr'] )
        writer.putMrsRegReg('r0','apsr-nzcvq')
        writer.putPushRegs([ 'r0'])
        writer.putNop();
        writer.putMovRegReg('r1', 'sp')
        writer.putBytes([ 0x5F, 0xF8, 0x18, 0x00]) // ldr.w	r0, [pc, #-0x18]
        writer.putBytes([ 0x5F, 0xF8, 0x20, 0x40]) // ldr.w	r4, [pc, #-0x20]
        writer.putBlxReg('r4')
        writer.putPopRegs(['r0'])
        writer.putMsrRegReg('apsr-nzcvq','r0')
        writer.putPopRegs(['r8', 'sb', 'sl', 'fp', 'ip', 'lr'] )
        writer.putPopRegs([ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7' ])
        writer.flush();
        let sz = writer.offset;
        return sz;
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        let funp = InlineHooker.loadm?.syms?.sh_inst_hook_thumb_rewrite;
        if(funp==undefined) throw `can not found sh_inst_hook_thumb_rewrite`;
        let fun = new NativeFunction(funp, 'int', ['pointer','pointer','uint','pointer']);
        let prewrite_len  = Memory.alloc(0x10); Memory.protect(prewrite_len,0x10, 'rwx')
        let offset = fun(from, to, sz, prewrite_len)
        if(offset <=0 ) throw `ret ${offset} when call sh_inst_hook_thumb_rewrite`
        let origin_bytes = readMemoryArrayBuffer(from,sz);
        let write_sz = offset;
        return [offset, origin_bytes]
    }

    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        let distance = to.or(1).sub(from.or(1)).toInt32();
        return distance >=-8388608 && distance<= 8388607;
    }

    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        if(this.canBranchDirectlyBetween(from, to)) return 4;
        else return 8;
    }

    putJumpCode(from:NativePointer, to:NativePointer):number {
        let code = from.and(~1);
        const writer = new ThumbWriter(code);
        if(this.canBranchDirectlyBetween(from,to)){
            writer.putBImm(to.or(1))
            writer.flush();
            return writer.offset;
        }
        else{
            if(code.and(0x3).equals(0)) {
                writer.putLdrRegRegOffset('pc','pc',0)
            }
            else{
                writer.putLdrRegRegOffset('pc','pc',2)
            }
            writer.flush()
            from.add(writer.offset).writePointer(to.or(1))
            return writer.offset+Process.pointerSize;
        }
    }

}

class ArmInlineHooker extends InlineHooker{

}

class Arm64InlineHooker extends InlineHooker{

    constructor(hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer){
        super(hook_ptr, trampoline_ptr, hook_fun_ptr,para1)
    }

    putPrecode(p:NativePointer):number {
        const writer = new Arm64Writer(p);
        writer.putPushAllXRegisters();              
        writer.putMovRegReg('x1','sp');             
        writer.putBytes([ 0x80, 0xfd, 0xff, 0x58]);  // 0x58: ldr  x0, trampoline_ptr.add(0x08)
        writer.putBytes([ 0x29, 0xfd, 0xff, 0x58]);  // 0x5c: ldr  x9, trampoline_ptr.add(0x00)
        writer.putBlrReg('x9');                     
        writer.putPopAllXRegisters();               
        writer.flush();
        return writer.offset;
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        let funp = InlineHooker.loadm?.syms?.sh_inst_hook_a64_rewrite;
        if(funp==undefined) throw `can not found sh_inst_hook_a64_rewrite`;
        let fun = new NativeFunction(funp, 'int', ['pointer','pointer','uint']);
        let offset = fun(from, to, sz)
        if(offset <0 ) throw `ret ${offset} when call sh_a64_inst_hook_rewrite`
        let origin_bytes = from.readByteArray(sz);
        if(origin_bytes==null) throw `can not read origin byte at ${from}`
        return [offset, origin_bytes]
    }

    relocCodeByFrida(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        let ioff=0;
        let offset = 0;
        for( let t=0;t<InlineHooker.max_code_cnt; t++) {
            if(ioff>=sz) break;
            let iaddr = from.add(ioff)
            let oaddr = to.add(offset);
            let inst = iaddr.readU32();
            offset+= sh_a64_rewrite(oaddr,inst,iaddr);
            ioff+=4;
        }
        let origin_bytes = readMemoryArrayBuffer(from, sz)
        return [offset, origin_bytes]
    }


    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        return new Arm64Writer(ptr(0)).canBranchDirectlyBetween(from, to);
    }

    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        if(this.canBranchDirectlyBetween(from, to)) return 4;
        else return 0x10;
    }

    putJumpCode(from:NativePointer, to:NativePointer):number {
        let code = from;
        const writer = new Arm64Writer(code);
        if(this.canBranchDirectlyBetween(from,to)){
            writer.putBImm(to)
            writer.flush();
            return writer.offset;
        }
        else{
            writer.putBytes([ 0x50, 0x00, 0x00, 0x58]);  // ldr	x16, #8
            writer.putBrReg('x16');
            writer.flush()
            from.add(writer.offset).writePointer(to)
            let sz = writer.offset+Process.pointerSize;
            return writer.offset+Process.pointerSize;
        }
    }
}