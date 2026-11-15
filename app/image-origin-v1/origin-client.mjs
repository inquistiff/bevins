import {MAX_IMAGE_BYTES,CHECK_TIMEOUT_MS,unavailable,validateSummary} from './protocol.mjs';
export {ORIGIN_COPY,ORIGIN_LIMIT,ORIGIN_ACTION} from './origin-result.mjs';

const wasmUrl=new URL('./runtime/resources/c2pa_bg.wasm',import.meta.url);
const workerUrl=new URL('./origin-worker.mjs',import.meta.url);
const wasmIntegrity='sha512-VUKUpwxCu08SShdzVBFmt9OjEBJBb8t0B0cJtO6liA3muW4/Y25yKpKTuu2MaTFNlsXhqkDeDg41/wn//UM2bw==';
let active=null,compiled=null,moduleLoad=null;

// One trusted asset load/compile can be in flight even when a caller cancels.
// Native compilation is not cancellable; sharing it prevents overlapping
// compilations across cancelled/restarted jobs. No image is captured here.
function loadModule() {
  if(compiled)return Promise.resolve(compiled);
  if(moduleLoad)return moduleLoad;
  const assetAbort=new AbortController();
  const timer=setTimeout(()=>assetAbort.abort(),CHECK_TIMEOUT_MS);
  moduleLoad=(async()=>{
    const response=await fetch(wasmUrl,{integrity:wasmIntegrity,credentials:'omit',cache:'force-cache',signal:assetAbort.signal});
    if(!response.ok)throw new Error();
    const wasm=await WebAssembly.compileStreaming(response);
    compiled=wasm;return wasm;
  })().finally(()=>{clearTimeout(timer);moduleLoad=null;});
  return moduleLoad;
}

export async function checkOrigin(file,{signal}={}) {
  if(signal?.aborted)return unavailable('cancelled');
  if(active)return unavailable('busy');
  if(!(file instanceof Blob)||file.size===0)return unavailable('unsupported_format');
  if(file.size>MAX_IMAGE_BYTES)return unavailable('oversize');
  const token=Symbol('origin');active=token;
  return await new Promise(resolve=>{
    let worker,settled=false;
    const abort=new AbortController();
    const current=()=>!settled&&active===token&&!abort.signal.aborted;
    const finish=result=>{
      if(settled)return;
      settled=true;clearTimeout(timer);
      signal?.removeEventListener('abort',cancel);
      abort.abort();worker?.terminate();worker=null;
      file=null;
      if(active===token)active=null;
      resolve(validateSummary(result));
    };
    const cancel=()=>finish(unavailable('cancelled'));
    const timer=setTimeout(()=>finish(unavailable('timeout')),CHECK_TIMEOUT_MS);
    signal?.addEventListener('abort',cancel,{once:true});
    // Avoid a signal race between the initial check and listener registration.
    if(signal?.aborted){cancel();return;}
    (async()=>{
      const header=new Uint8Array(await file.slice(0,12).arrayBuffer());
      if(!current())return;
      const jpeg=header[0]===255&&header[1]===216&&header[2]===255;
      const png=[137,80,78,71,13,10,26,10].every((b,i)=>header[i]===b);
      if(!jpeg&&!png){finish(unavailable('unsupported_format'));return;}
      let wasm;
      try {wasm=await loadModule();}
      catch (_){if(current())finish(unavailable('asset_unavailable'));return;}
      if(!current())return;
      const blob=new Blob([file],{type:jpeg?'image/jpeg':'image/png'});
      worker=new Worker(workerUrl,{type:'module',name:'bevins-image-origin'});
      worker.onmessage=e=>{if(current())finish(validateSummary(e.data));};
      worker.onerror=()=>{if(current())finish(unavailable());};
      worker.onmessageerror=()=>{if(current())finish(unavailable('invalid_result'));};
      if(!current()){worker.terminate();worker=null;return;}
      worker.postMessage({wasm,blob});
    })().catch(()=>{if(current())finish(unavailable());});
  });
}
