
'use strict';

export let _frida_log = new NativeCallback(function(sp:NativePointer){
        let s = sp.readUtf8String();
        console.log(s)
},'void',['pointer']);

export let _frida_err = new NativeCallback(function(sp:NativePointer){
    let s = sp.readUtf8String();
    console.log(s)
    throw `error occured`;
    return ;
},'void',['pointer']);

export let _frida_hexdump = new NativeCallback(function(sp:NativePointer, l:number){
    console.log(hexdump(sp, {
        offset: 0,
        length: l,
        header: true,
        ansi: false
    }));
},'void',['pointer','uint']);

export let logWithFileNameAndLineNo = (msg:string)=>{
    let getErrorObject = function(){
        try{throw Error('');} catch(err) {return err;}
    }
    let err = getErrorObject() as Error;
    const caller_line = err.stack!=undefined?err.stack.split("\n")[3] : "unknow line";
    // remove `at `
    let index = caller_line?.indexOf('at ');
    let final_caller_line = (index>=0) ?caller_line.slice(index+3) : caller_line;
    console.log(final_caller_line, ":", msg)
}

export let showAsmCode = (p:NativePointer, sz?: number| undefined)=>{
    if (sz == undefined) sz = 5*Process.pointerSize;
    for(let offset = 0; offset<sz; ){
        let addr = p.add(offset);
        try{
            let inst;
            switch(Process.arch){
                case "arm":     inst = Instruction.parse(addr) as ArmInstruction;   break;
                case "arm64":   inst = Instruction.parse(addr) as Arm64Instruction; break;
                case "mips":    inst = Instruction.parse(addr) as MipsInstruction;  break;
                case "ia32":    inst = Instruction.parse(addr) as X86Instruction;   break;
                case "x64":     inst = Instruction.parse(addr) as X86Instruction;   break;
            }
            console.log(addr.and(~1), ptr(offset), inst.toString())
            offset+= inst.size;
        }
        catch(e){
            console.log(`can not parse instruction at ${addr}`)
            dumpMemory(addr.and(~1),Process.pointerSize)
            offset += Process.pointerSize;
        }
    }
}

export let dumpMemory = (p:NativePointer, l?:number|undefined)=>{
    if (l == undefined) l = 0x20;
    console.log(hexdump(p, {
        offset: 0,
        length: l,
        header: true,
        ansi: false
    }));
};

export let androidOutput = (s:string)=>{
    let funp = Module.getExportByName(null,'__android_log_print')
    let fun = new NativeFunction(funp, 'int',['int','pointer','pointer'])
    fun(0, Memory.allocUtf8String("frida"), Memory.allocUtf8String(s))
}

export let getPyCodeFromMemory=(p:NativePointer, sz:number):string=>{
    let pycode = "";
    pycode += `(${p}, [`
    let bs = p.readByteArray(sz)
    if(bs==null) throw `can not read at ${sz}`
    pycode += new Uint8Array(bs).join(',')
    pycode += ']), '
    console.log(pycode)
    return pycode;
}

export let readMemoryArrayBuffer=(p:NativePointer, sz?:number):ArrayBuffer=>{
    if(sz==undefined) sz = 0x10;
    let ab = p.readByteArray(sz);
    if(ab==null) throw(`read ${sz} bytes from ${p} failed`)
    return ab;
}

export let readBinaryFromFileWithRange=(fn:string, p:NativePointer, sz:number, offset:number)=>{
    let cm = new CModule(`
        typedef unsigned int size_t;
        extern void _frida_err(char * );
        extern int fseek(void *stream, long offset, int whence);
        extern size_t fread(void *ptr, size_t size, size_t nmemb, void *stream);
        extern int fclose(void *stream);
        extern void *fopen( char *pathname,  char *mode);
        #define SEEK_SET 0
        int fun(char* fn, void*p, unsigned int sz, unsigned int offset ){
            void* fp = fopen(fn, "rb");
            if(!fp) _frida_err("can not open file ");
            fseek(fp, offset, SEEK_SET);
            fread(p, 1, sz, fp);
            fclose(fp);
            return 0;
        }
    `,{
        _frida_err : _frida_err,
        fopen : Module.getExportByName(null,'fopen'),
        fseek : Module.getExportByName(null,'fseek'),
        fread : Module.getExportByName(null,'fread'),
        fclose: Module.getExportByName(null,'fclose'),
    })

    let fun = new NativeFunction(cm.fun, 'int',['pointer', 'pointer', 'uint', 'uint']);
    return fun(Memory.allocUtf8String(fn), p, sz, offset);
}

