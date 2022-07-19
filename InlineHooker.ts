
'use strict';

import { showAsmCode, dumpMemory, getPyCodeFromMemory } from "./fridautils";

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
            [sz, origin_bytes] = this.relocCode(this.hook_ptr, code.add(offset), relocsz); offset += sz;
            // write jump back code 
            let origin_inst_len = origin_bytes.byteLength;
            sz = this.putJumpCode(code.add(offset), this.hook_ptr.add(origin_inst_len)); offset += sz;

            // show code 
            dumpMemory(code, offset)
            getPyCodeFromMemory(code, offset)
        });  
        // write jump code at hook_ptr
        let jumpsz = this.getJumpInstLen(this.hook_ptr, trampolineCodeAddr);
        let bs = this.hook_ptr.readByteArray(jumpsz);
        if(bs==null) throw `can not read byte at ${this.hook_ptr}`
        origin_bytes = bs;
        Memory.patchCode(this.hook_ptr, jumpsz, code=>{
            let sz = this.putJumpCode(code, trampolineCodeAddr)
            dumpMemory(code, sz);
            getPyCodeFromMemory(code, sz)
        })
        console.log('trampolineCodeAddr', trampolineCodeAddr)
        console.log('hook_fun_ptr', this.hook_fun_ptr);
        console.log('origin_bytes', origin_bytes)
        return [offset, origin_bytes];
    }

    static all_inline_hooks:{[key:string]:{
            origin_bytes:ArrayBuffer| null,
            hook_ptr:NativePointer,
    }}= { };

    static hasHooked = (hook_ptr:NativePointer):boolean=>{
        return hook_ptr.toString() in InlineHooker.all_inline_hooks;
    }

    static restoreAllInlineHooks=()=>{
        let hooks = InlineHooker.all_inline_hooks;
        console.log('all_inline_hooks', Object.keys(hooks).length)
        Object.keys(hooks)
            .forEach(k=>{
                let v = hooks[k]
                console.log('k',k, JSON.stringify(v))
                if (v.origin_bytes!=null){
                    let bs = v.origin_bytes;
                    let p = v.hook_ptr;
                    let sz = bs.byteLength;
                    Memory.patchCode(p,sz, code=>{
                        const writer = new Arm64Writer(code)
                        writer.putBytes(bs)
                        writer.flush()
                        showAsmCode(code,sz)
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
        return writer.offset;
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        console.log('relocCode sz', sz, from, '=>', to);
        let offset = 0;
        let code = to.and(~1);
        const writer = new ThumbWriter(code);
        const relocator = new ThumbRelocator(from, writer)
        for(let c=0;c<InlineHooker.max_code_cnt; c++){
            dumpMemory(to.add(offset), 0x10)
            dumpMemory(from.add(offset), 0x10)
            offset = relocator.readOne(); 
            let inst = relocator.input;
            console.log(offset, 'inst', JSON.stringify(inst))
            relocator.writeOne();
            if(offset>=sz) break;
        }
        writer.flush();
        let origin_bytes = from.readByteArray(offset);
        if(origin_bytes==null) throw `can not read origin byte at ${from}`
        return [writer.offset, origin_bytes]
    }

    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        let distance = to.or(1).sub(from.or(1)).toInt32();
        console.log('from', from)
        console.log('to', to)
        console.log('distance', distance);
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
            console.log(from,'=>', to.or(1))
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
        console.log('relocCode sz', sz, from, '=>', to);
        let offset = 0;
        let code = to.and(~1);
        const writer = new Arm64Writer(code);
        const relocator = new Arm64Relocator(from, writer)
        for(let c=0;c<InlineHooker.max_code_cnt; c++){
            dumpMemory(to.add(offset), 0x10)
            dumpMemory(from.add(offset), 0x10)
            offset = relocator.readOne(); 
            let inst = relocator.input;
            console.log(offset, 'inst', JSON.stringify(inst))
            relocator.writeOne();
            if(offset>=sz) break;
        }
        writer.flush();
        let origin_bytes = from.readByteArray(offset);
        if(origin_bytes==null) throw `can not read origin byte at ${from}`
        return [writer.offset, origin_bytes]
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
            console.log(from,'=>', to)
            writer.putBytes([ 0x50, 0x00, 0x00, 0x58]);  // ldr	x16, #8
            writer.putBrReg('x16');
            writer.flush()
            from.add(writer.offset).writePointer(to)
            return writer.offset+Process.pointerSize;
        }
    }
}