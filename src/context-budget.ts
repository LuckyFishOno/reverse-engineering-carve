export function responseBudget(value:number|undefined){const n=value??8192;if(!Number.isInteger(n)||n<1024||n>65536)throw new Error('Use budgetBytes1024–65536 (compact UTF8 JSON payload, excluding transport framing).');return n;}
export function measured<T extends Record<string,any>>(body:T,budgetBytes:number,rawSelectedTextBytes?:number){
 const result={...body,receipt:{budgetBytes,responseBytes:0,estimatedTokens:0,tokenEstimate:'ceil(UTF8 response bytes /4); heuristic, not a model tokenizer or billing measurement',...(rawSelectedTextBytes===undefined?{}:{rawSelectedTextBytes})}};
 for(let n=0;n<12;n++){const bytes=Buffer.byteLength(JSON.stringify(result));if(bytes===result.receipt.responseBytes)return result;result.receipt.responseBytes=bytes;result.receipt.estimatedTokens=Math.ceil(bytes/4);}
 throw new Error('Could not establish the response byte receipt.');
}
export function budgetItems<T>(base:Record<string,any>&{total:number;offset:number},candidates:{value:T;rawBytes?:number}[],budgetBytes:number){
 const selected:{value:T;rawBytes?:number}[]=[];
 const seal=()=>measured({...base,items:selected.map(r=>r.value),nextOffset:base.offset+selected.length<base.total?base.offset+selected.length:null,budgetLimited:selected.length<candidates.length},budgetBytes,selected.some(r=>r.rawBytes!==undefined)?selected.reduce((n,r)=>n+(r.rawBytes??0),0):undefined);
 let result=seal();if(result.receipt.responseBytes>budgetBytes)throw new Error('Response metadata exceeds budgetBytes; increase the budget.');
 for(const candidate of candidates){selected.push(candidate);const next=seal();if(next.receipt.responseBytes>budgetBytes){selected.pop();if(!selected.length)throw new Error('Budget cannot hold one complete result; use at least'+next.receipt.responseBytes+' bytes.');return seal();}result=next;}
 return result;
}
