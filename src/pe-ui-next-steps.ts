// Investigation guidance only: these tasks neither execute REA nor establish closure.
export function peUiNextSteps(row:Record<string,any>,visited:Set<string>){
 const steps:Record<string,any>[]=[];
 const add=(action:string,reason:string,target:Record<string,any>={})=>steps.push({action,reason,...Object.fromEntries(Object.entries(target).filter(([,value])=>value!==undefined))});
 if(row.kind==='ui-entry'){
  if(row.status==='candidate-only')add('import-function','Import complete entry code from the separate REA process.',{file:row.file,address:row.address});
  else if(row.status==='ambiguous-function-evidence')add('select-evidence','Choose one compatible entry observation explicitly.');
  else if(row.status!=='static-entry-matched')add('locate-ui-handler','Locate a handler candidate for the selected command before expanding dependencies.');
 }
 if(row.kind==='function-coverage'){
  if(row.relationshipsIncomplete)add('capture-relationships','Capture missing call and reference coverage from the separate REA process.');
  if(row.nonCallReferences>0)add('inspect-state-resources','Inspect recorded data references for state and resource dependencies.');
 }
 if(row.kind==='unresolved-call'){
  add('resolve-call','Investigate the recorded unresolved call without guessing its destination.');
  if(row.resourceApi)add('review-resource-api','Review byte-bound import arguments while retaining the unresolved call and module/language uncertainty.',{file:row.file,address:row.address});
 }
 if(row.kind==='data-reference'){
  if(row.resourceAssociation?.matchesTotal)add('review-resource','Review the exact resource payload/path and language; containment does not prove runtime use.',{file:row.file,address:row.targetAddress});
  if(row.state==='mutable-state-candidate')add('model-state','Declare initialization, updates and reset/persistence behavior before reconstruction.',{file:row.file,address:row.targetAddress});
  else if(row.status!=='file-bytes-captured')add('resolve-data-reference','Investigate the unresolved data location; no runtime value is inferred.',{file:row.file,address:row.targetAddress});
  else add('review-data-extent','Review the object type and extent; captured bytes are a bounded prefix, not a complete dependency.',{file:row.file,address:row.targetAddress});
 }
 if(row.kind==='call-dependency'){
  if(row.resourceApi)add('review-resource-api','Review declared API arguments, module identity and language selection; caller-image matches are candidates only.',{file:row.file,address:row.callSite});
  const target={file:row.file,address:row.address,callerObservationId:row.from};
  if(row.status==='missing-function-code'){
   if(row.external||!/^0x[0-9a-f]+$/.test(row.address??''))add('inspect-call-target','Resolve the call target and capture typed call evidence before selecting dependency code.',target);
   else add('import-function','Import complete callee code using the caller source and analysis profile.',target);
  }
  if(row.status==='ambiguous-function-evidence'||row.status==='ambiguous-dll-export')add('select-evidence','Select one compatible dependency observation; alternatives are not resolved automatically.',target);
  if(row.status==='import-target-unresolved')add('resolve-import','Investigate the selected import definition, including forwarders or API-set routing where applicable.',{...target,module:row.importWitness?.slot.module,name:row.importWitness?.slot.name,ordinal:row.importWitness?.slot.ordinal});
  if(row.expansion==='depth-limit'&&row.matches?.length===1&&!visited.has(row.matches[0].observationId))add('expand-depth','Increase dependencyDepth within its supported bounds or inspect this observation separately through REA.',{observationId:row.matches[0].observationId});
 }
 return steps;
}
