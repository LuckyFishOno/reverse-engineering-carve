/** Fixed-width keys preserve unsigned address ordering in SQLite without Number precision loss. */
export function addressKey(address:string){
  const match=/^(?:(.+):)?(?:0x)?([a-fA-F0-9]{1,32})$/.exec(address);if(!match)throw new Error('Invalid program address.');
  return{space:match[1]??'',key:match[2]!.toLowerCase().padStart(32,'0'),offset:BigInt('0x'+match[2])};
}
export function windowRange(address:string,bytes:number){
  if(!Number.isInteger(bytes)||bytes<1||bytes>4096)throw new Error('Invalid native window size.');
  const start=addressKey(address);const end=start.offset+BigInt(bytes)-1n;if(end>=1n<<128n)throw new Error('Native address range overflow.');
  return{space:start.space,start:start.key,end:end.toString(16).padStart(32,'0')};
}
