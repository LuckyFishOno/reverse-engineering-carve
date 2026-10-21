// Source-owned CRC session reconstruction. One module instance per sequence.
let state=0xffffffff;
export function update(bytes){
 if(!Array.isArray(bytes)||bytes.length>4096||bytes.some(v=>!Number.isInteger(v)||v<0||v>255))throw new RangeError('Bounded bytes required');
 for(const byte of bytes){state=(state^byte)>>>0;for(let bit=0;bit<8;bit++)state=((state>>>1)^((state&1)?0xedb88320:0))>>>0;}
 return state;
}
