# Frida-Android-Onlinehook
An online hook library based on Frida, only supports android Arm64 now.
# Concept
The library just let us invoke a function when the process reach to a specific instructions.
# Usage
```typescript
import {InlineHooker} from './src/InlineHooker'

// define the function will be invoked
const frida_fun = new NativeCallback(function(para1:NativePointer, sp:NativePointer){
    console.log("para1", para1, "sp",sp)
 }, "void", ["pointer", "pointer"]);

// inline
const hook_ptr = ... ; // the hook pointer
const trampoline_ptr =   ...; // We should alloc a memory to store trampoline code, and don't define it as local variable, or javascript GC system will free the alloced memory automatically, and the process will crash when it reach to hook_ptr
const para1 = ... ; //  this parameter will be pass to our frida_fun as para1;
let sz = InlineHooker.inlineHookPatch(trampoline_ptr,hook_ptr, frida_fun, para1);
// returnd sz is the length of the trampoline code
```
# TODO
- Support more OS.
- Support more architecture

