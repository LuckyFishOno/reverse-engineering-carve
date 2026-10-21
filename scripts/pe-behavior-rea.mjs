// Explicit test-client orchestration of an independent REA MCP, not a RECarve server proxy.
import path from 'node:path';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
export async function collectPeBehaviorEvidence(out,images,engines,reaInstall,targets=[['quote.exe',[['quote',images.entry],['blocks',images.blocks]]],['rate.dll',[['rate',images.rate]]]],options={}){
 const pkg=JSON.parse(await readFile(path.join(reaInstall,'node_modules/rea-agents/package.json'),'utf8'));if(pkg.version!=='6.7.0')throw new Error('This integration pins REA6.7.0.');
 const bin=path.join(reaInstall,'node_modules/rea-agents',typeof pkg.bin==='string'?pkg.bin:pkg.bin.rea),temporary=path.join(out,'tmp'),producer=path.join(out,'producer');await mkdir(temporary,{recursive:true});await mkdir(producer,{recursive:true});
 const transport=new StdioClientTransport({command:process.execPath,args:[bin,'mcp'],cwd:out,stderr:'pipe',env:{PATH:process.env.PATH??'/usr/bin:/bin',LANG:'C.UTF-8',REA_ANALYSIS_PROVIDER:'ghidra',GHIDRA_INSTALL_DIR:engines.ghidra,JAVA_HOME:engines.javaHome,GHIDRA_HEADLESS_MAXMEM:'1024M',GHIDRA_MAXMEM:'1024M',TMPDIR:temporary}}),client=new Client({name:'owned-pe-behavior-evidence',version:'1'});let diagnostics='';transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-16000);});
 const call=async(name,args)=>{const r=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(r.isError)throw new Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return r.structuredContent??JSON.parse(r.content.find(c=>c.type==='text').text);};
 const result={version:pkg.version,pid:null,records:[],closed:false};
 try{
  await client.connect(transport);result.pid=transport.pid;
  for(const [file,functions] of targets){
   await call('open_binary',{path:path.join(out,'input',file),provider_id:'ghidra'});
   for(const [label,address] of functions){
    const paths={};for(const [role,tool] of [['code','procedure_pseudo_code'],['info','procedure_info'],['callees','procedure_callees'],['references','procedure_references'],...(options.instructions?[['instructions','read_function_instructions']]:[])]){
     const r=await call(tool,{procedure:address,...(role==='references'?{direction:'outgoing'}:{})}),p=path.join(producer,label+'-'+role+'.json');await writeFile(p,JSON.stringify(r,null,2)+'\n');paths[role]=p;
    }
    result.records.push({file,label,address,...paths});console.log('Captured real REA function '+label+' '+address);
   }
   await call('close_binary',{});
  }
  await client.close();result.closed=true;await writeFile(path.join(out,'producer-index.json'),JSON.stringify(result,null,2)+'\n');return result;
 }finally{await client.close();await writeFile(path.join(out,'rea-diagnostics.log'),diagnostics);}
}
