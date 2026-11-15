import {createC2pa,Reader,Context} from './runtime/index.js';
import {normalizeOrigin} from './origin-result.mjs';
import {MAX_IMAGE_BYTES,unavailable,validateSummary} from './protocol.mjs';

let started=false;
self.onmessage=async ({data})=>{
  if(started)return;
  started=true;
  let sdk,reader,result=unavailable();
  try {
    if (!(data?.wasm instanceof WebAssembly.Module) || !(data?.blob instanceof Blob) ||
        data.blob.size<=0 || data.blob.size>MAX_IMAGE_BYTES || !['image/jpeg','image/png'].includes(data.blob.type)) {
      self.postMessage(unavailable('unsupported_format'));self.close();return;
    }
    // A fixed same-origin HTTPS module avoids revocable blob-worker startup.
    sdk=await createC2pa({wasmSrc:data.wasm,workerSrc:new URL('./runtime/c2pa_worker.js',import.meta.url)});
    const context=new Context({verify:{verifyAfterReading:true,verifyTrust:true,
      verifyTimestampTrust:true,ocspFetch:false,remoteManifestFetch:false}});
    reader=await Reader.fromBlob(sdk,data.blob.type,data.blob,context);
    const store=reader?await reader.manifestStore():null;
    // Full stores never leave this isolated worker. No metadata is fetched,
    // rendered, persisted, returned, or treated as a model instruction.
    const normalized=normalizeOrigin({ok:true,store});
    result=validateSummary({...normalized,reason:normalized.status==='unavailable'?'reader_unavailable':null});
  } catch (_) {
    result=unavailable();
  } finally {
    try {if(reader)await reader.free();} catch (_) {}
    try {sdk?.dispose();} catch (_) {}
  }
  self.postMessage(result);
  self.close();
};
