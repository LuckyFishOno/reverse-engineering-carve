import {crcUpdate} from '../pe-crc/implementation.mjs';
// Reviewed initializer recurrence; return an independent table to each caller.
export function generateCrcTables() {
  const table=Array(2048);
  for(let i=0;i<256;i++){
    let value=i;
    for(let bit=0;bit<8;bit++)value=((value>>>1)^((value&1)?0xedb88320:0))>>>0;
    table[i]=value;
  }
  for(let i=256;i<2048;i++){const previous=table[i-256];table[i]=((previous>>>8)^table[previous&255])>>>0;}
  return table;
}
const table=Object.freeze(generateCrcTables().slice(0,256));
export function crcDispatch(profile,state,bytes,alignment) {
  if((profile!==0&&profile!==1)||!Number.isInteger(alignment)||alignment<0||alignment>7)throw new RangeError('CPU predicate0or1and alignment0to7required');
  return {value:crcUpdate(state,bytes,table),implementation:profile?'T4':'T8'};
}
// Scalar result for generated original initialization/dispatch verification tasks.
export function crcValue(state,bytes){return crcUpdate(state,bytes,table);}
