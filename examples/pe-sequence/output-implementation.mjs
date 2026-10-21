// Owned output transform reconstruction; one state per sequence.
let state=0xffffffff;
export function transform(bytes,capacity){
 if(!Array.isArray(bytes)||bytes.length>4096||bytes.some(v=>!Number.isInteger(v)||v<0||v>255)||!Number.isInteger(capacity)||capacity<0||capacity>4096)throw new RangeError('Bounded bytes and output capacity required');
 const target=Array(capacity).fill(null),count=Math.min(bytes.length,capacity);
 for(let i=0;i<count;i++){const byte=bytes[i];target[i]=byte^(state&255);state=(state^byte)>>>0;for(let bit=0;bit<8;bit++)state=((state>>>1)^((state&1)?0xedb88320:0))>>>0;}
 return {returnValue:count,outputs:{target}};
}
