// The reusable operation projects copied archive metadata. It neither reads/extracts
// archive content nor installs or executes a bootstrap package.
export function queryBootstrapCatalog(metadata,entries,query={}) {
  if(!query||typeof query!=='object'||Array.isArray(query)||Object.getPrototypeOf(query)!==Object.prototype||Object.keys(query).some(k=>!['prefix','offset','limit'].includes(k)))throw new TypeError('Expected a plain catalog query');
  const {prefix='',offset=0,limit=20}=query;
  if(typeof prefix!=='string'||prefix.length>256||!Number.isInteger(offset)||offset<0||offset>1000000||!Number.isInteger(limit)||limit<1||limit>100)throw new RangeError('Catalog query outside the declared domain');
  const selected=entries.filter(e=>e.name.startsWith(prefix)),items=selected.slice(offset,offset+limit).map(e=>({...e}));
  return {...metadata,matchedEntries:selected.length,items,nextOffset:offset+items.length<selected.length?offset+items.length:null};
}
