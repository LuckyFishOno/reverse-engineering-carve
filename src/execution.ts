import { spawn } from 'node:child_process';

export type Outcome = { kind: 'return'; value: unknown } | { kind: 'throw'; error: { name: string; message: string } }
  | { kind: 'harness-error'; detail: string };
function workerSource(sequence:boolean){return `import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const send = result => { writeFileSync(3, JSON.stringify(result)); process.exit(0); };
try {
  const args = JSON.parse(readFileSync(0, 'utf8'));
  let module;
  try { module = await import(pathToFileURL(process.argv[2]).href); }
  catch (error) { send({ kind: 'harness-error', detail: 'Reference/candidate import failed: ' + error.message }); }
  const name = process.argv[3];
  const fn = Object.hasOwn(module, name) ? module[name] : module.default?.[name];
  if (typeof fn !== 'function') send({ kind: 'harness-error', detail: 'Export is not a function: ' + name });
  const call = async positional => {
    let value;
    try { value = await fn(...positional); }
    catch (error) { return { kind: 'throw', error: { name: String(error?.name ?? 'Error'), message: String(error?.message ?? error) } }; }
    try {
      const json = JSON.stringify(value, (_key, item) => {
        if (typeof item === 'number' && !Number.isFinite(item)) throw new Error('Non-finite return value');
        return item;
      });
      if (json === undefined) throw new Error('Return value is not JSON');
      return { kind: 'return', value: JSON.parse(json) };
    } catch (error) { throw new Error('Return serialization failed: ' + error.message); }
  };
  if (${sequence}) {
    const results=[];
    for (const positional of args) results.push(await call(positional));
    send({kind:'return',value:results});
  } else send(await call(args));
} catch (error) { send({ kind: 'harness-error', detail: error.message }); }
`;}
export const worker=workerSource(false);
export const sequenceWorker=workerSource(true);

export function run(workerPath: string, entry: string, exportName: string, args: unknown[], cwd: string, timeoutMs: number, restricted = false, signal?: AbortSignal): Promise<Outcome> {
  if (signal?.aborted) return Promise.resolve({ kind: 'harness-error', detail: 'Execution cancelled.' });
  return new Promise(resolve => {
    const permissionFlags = restricted ? ['--permission', `--allow-fs-read=${cwd}`, `--allow-fs-read=${workerPath}`] : [];
    const child = spawn(process.execPath, [...permissionFlags, workerPath, entry, exportName], {
      cwd, detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH, TEMP: cwd, TMP: cwd, TMPDIR: cwd, HOME: cwd, LANG: 'C.UTF-8' }
    });
    const result: Buffer[] = []; let bytes = 0; let failure = ''; let settled = false; let diagnostic = '';
    function kill() {
      if (!child.pid) return;
      try { if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL'); } catch { /* already exited */ }
    }
    const abort = () => { failure = 'Execution cancelled.'; kill(); };
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    const timer = setTimeout(() => { failure = `Execution timed out after ${timeoutMs} ms`; kill(); }, timeoutMs);
    const count = (data: Buffer) => { bytes += data.length; if (bytes > 1024 * 1024) { failure = 'Execution output exceeded 1 MiB'; kill(); } };
    child.stdout!.on('data', count); child.stderr!.on('data', (data: Buffer) => { count(data); if (diagnostic.length < 2048) diagnostic += data.toString().slice(0, 2048 - diagnostic.length); });
    const protocol = child.stdio[3] as NodeJS.ReadableStream;
    protocol.on('data', (data: Buffer) => { count(data); if (!failure) result.push(data); });
    const finish = (outcome: Outcome) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); kill(); resolve(outcome); };
    child.on('error', error => finish({ kind: 'harness-error', detail: error.message }));
    child.on('close', () => {
      if (failure) return finish({ kind: 'harness-error', detail: failure });
      try {
        const outcome = JSON.parse(Buffer.concat(result).toString('utf8')) as Outcome;
        if (!['return', 'throw', 'harness-error'].includes(outcome.kind)) throw new Error('Invalid worker result');
        finish(outcome);
      } catch { finish({ kind: 'harness-error', detail: 'Execution exited without a valid result' + (diagnostic ? ': ' + diagnostic : '') }); }
    });
    child.stdin!.on('error', () => {});
    child.stdin!.end(JSON.stringify(args));
  });
}

