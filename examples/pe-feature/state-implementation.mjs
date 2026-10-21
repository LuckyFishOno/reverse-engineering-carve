// Reviewed owned state_command reconstruction; each invocation creates one isolated session.
export function stateSequence(steps){
 if(!Array.isArray(steps)||steps.length<1||steps.length>64)throw new RangeError('One to64steps required');
 let counter=7;const rates=[2,5,9],label='counter\0';
 return steps.map(args=>{
  if(!Array.isArray(args)||args.length!==2||args.some(n=>!Number.isInteger(n)||n<-2147483648||n>2147483647))throw new RangeError('Two signed32arguments required per step');
  const [operation,value]=args;let result;
  if(operation===0){counter=0;result=0;}
  else if(operation===1){if(value<0)result=-2;else{counter=(counter+value*rates[value%3])>>>0;result=counter|0;}}
  else if(operation===2)result=counter|0;
  else if(operation===3)result=label.charCodeAt(value&7);
  else if(operation===4)result='ready'.charCodeAt((value>>>0)%5);
  else result=-1;
  return {kind:'return',value:result};
 });
}
