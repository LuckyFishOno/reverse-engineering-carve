// Independent bounded reconstruction of visible BitArray state, not recovered source.
// One module instance owns one object. "new" is an adapter lifecycle operation.
let bits=[];
const integer=(value,min,max)=>Number.isInteger(value)&&value>=min&&value<=max;
export function bitArrayStep(operation,...args){
  if(typeof operation!=='string')throw new TypeError('Expected an operation name.');
  switch(operation){
    case 'read': case 'clear': case 'reverse': case 'new':
      if(args.length!==0)throw new TypeError('Operation takes no arguments.');
      break;
    case 'append':
      if(args.length!==2||!integer(args[0],-2147483648,2147483647)||!integer(args[1],0,32)||bits.length+args[1]>4096)throw new TypeError('Expected signed32 value, count0–32 and total size<=4096.');
      break;
    case 'set': case 'flip':
      if(args.length!==1||!integer(args[0],0,bits.length-1))throw new TypeError('Expected an existing bit index.');
      break;
    default: throw new TypeError('Unknown operation.');
  }
  switch(operation){
    case 'new': bits=[];break;
    case 'clear': bits.fill(false);break;
    case 'reverse': bits.reverse();break;
    case 'append': for(let shift=args[1]-1;shift>=0;shift--)bits.push(((args[0]>>>shift)&1)===1);break;
    case 'set': bits[args[0]]=true;break;
    case 'flip': bits[args[0]]=!bits[args[0]];break;
  }
  return{size:bits.length,sizeInBytes:Math.ceil(bits.length/8),bits:bits.map(bit=>bit?'1':'0').join('')};
}
