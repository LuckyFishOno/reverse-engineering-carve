// Bounded straight-line x86 argument stack; entry memory/register values are unknown.
export function decodeResourceArgumentPrefix32(code:Buffer,limits:{instructions:number;stackWords:number}){
 const regs:(bigint|null)[]=Array(8).fill(null),stack:(bigint|null)[]=[],instructions:{offset:number;bytes:string;operation:string}[]=[];let p=0;
 const stop=(reason:string)=>({complete:false,reason,offset:p,instructions,arguments:null});
 while(p<code.length){
  if(instructions.length>=limits.instructions)return stop('instruction-limit');
  const start=p,op=code[p++]!,finish=(operation:string)=>instructions.push({offset:start,bytes:code.subarray(start,p).toString('hex'),operation});
  const push=(value:bigint|null)=>{if(stack.length>=limits.stackWords)return false;stack.unshift(value);return true;};
  if(op===0x90){finish('nop');continue;}
  if(op>=0xb8&&op<=0xbf){const dst=op-0xb8;if(dst===4||p+4>code.length)return stop('unsupported-or-truncated-move');regs[dst]=BigInt(code.readUInt32LE(p));p+=4;finish('mov-immediate');continue;}
  if(op===0x68||op===0x6a){const n=op===0x68?4:1;if(p+n>code.length)return stop('truncated-push');const value=n===4?BigInt(code.readUInt32LE(p)):BigInt.asUintN(32,BigInt(code.readInt8(p)));p+=n;if(!push(value))return stop('stack-limit');finish('push-immediate');continue;}
  if(op>=0x50&&op<=0x57){if(!push(regs[op-0x50]??null))return stop('stack-limit');finish('push-register');continue;}
  if(op>=0x58&&op<=0x5f){const dst=op-0x58;if(dst===4)return stop('stack-register-write-not-supported');regs[dst]=stack.shift()??null;finish('pop-register');continue;}
  if(op===0xff){
   if(p>=code.length)return stop('truncated-push');const modrm=code[p++]!,mod=modrm>>6,rm=modrm&7;
   if(((modrm>>3)&7)!==6)return stop('unsupported-instruction-or-control-flow');
   if(mod===3){if(!push(regs[rm]??null))return stop('stack-limit');finish('push-register');continue;}
   const n=mod===1?1:mod===2?4:0;
   if(rm===4){if(code[p++]!==0x24)return stop('address-expression-not-supported');}else if(rm!==5||mod===0)return stop('address-expression-not-supported');
   if(p+n>code.length)return stop('truncated-push');p+=n;if(!push(null))return stop('stack-limit');finish('push-unknown-stack-value');continue;
  }
  if((op===0x83||op===0x81)&&(code[p]===0xec||code[p]===0xc4)){
   const modrm=code[p++]!,n=op===0x83?1:4;if(p+n>code.length)return stop('truncated-stack-adjustment');const amount=n===1?code.readInt8(p):code.readInt32LE(p);p+=n;
   if(amount<0||amount%4!==0||amount/4>limits.stackWords)return stop('stack-adjustment-not-supported');
   if(modrm===0xec){if(stack.length+amount/4>limits.stackWords)return stop('stack-limit');stack.unshift(...Array(amount/4).fill(null));}else stack.splice(0,amount/4);
   finish('stack-adjustment');continue;
  }
  if(op===0x31||op===0x33||op===0x89||op===0x8b||op===0x8d){
   if(p>=code.length)return stop('truncated-register-instruction');const modrm=code[p++]!,mod=modrm>>6,reg=(modrm>>3)&7,rm=modrm&7;
   if(mod!==3){
    if((op!==0x8b&&op!==0x8d)||reg===4)return stop('memory-operation-not-supported');
    let displacement=mod===1?1:mod===2?4:0;
    if(rm===4){if(code[p++]!==0x24)return stop('address-expression-not-supported');}
    else if(rm!==5||mod===0)return stop('address-expression-not-supported');
    if(p+displacement>code.length)return stop('truncated-address-expression');p+=displacement;regs[reg]=null;finish(op===0x8d?'stack-address':'unknown-stack-load');continue;
   }
   if(op===0x8d)return stop('invalid-register-address-expression');const dst=op===0x33||op===0x8b?reg:rm,src=op===0x33||op===0x8b?rm:reg;
   if(dst===4)return stop('stack-register-write-not-supported');
   if(op===0x31||op===0x33){if(dst!==src)return stop('nonzero-xor-not-supported');regs[dst]=0n;finish('xor-self');}
   else{regs[dst]=regs[src]??null;finish('mov-register');}continue;
  }
  return stop('unsupported-instruction-or-control-flow');
 }
 const hex=(v:bigint|null|undefined)=>v===null||v===undefined?null:'0x'+v.toString(16);
 return {complete:true,reason:null,offset:p,instructions,arguments:{stack0:hex(stack[0]),stack1:hex(stack[1]),stack2:hex(stack[2]),stack3:hex(stack[3])}};
}
