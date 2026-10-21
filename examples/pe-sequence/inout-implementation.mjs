// Owned in-place transform reconstruction; one isolated session per sequence.
let state=0xffffffff;
export function inplace(bytes,limit){
 if(!Array.isArray(bytes)||bytes.length>4096||bytes.some(v=>!Number.isInteger(v)||v<0||v>255)||!Number.isInteger(limit)||limit<0||limit>0xffffffff)throw new RangeError('Bounded bytes and uint32 limit required');
 const target=bytes.slice(),count=Math.min(target.length,limit);
 for(let i=0;i<count;i++){const byte=target[i];target[i]=byte^(state&255);state=(state^byte)>>>0;for(let bit=0;bit<8;bit++)state=((state>>>1)^((state&1)?0xedb88320:0))>>>0;}
 return {returnValue:count,outputs:{target}};
}
