import { spawn } from 'node:child_process';
import { open, mkdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { inventory } from './artifact.js';

export async function analyzeWithRea(input: string, output: string, executable = 'rea') {
  const target = await inventory(input);
  if (target.kind === 'javascript') throw new Error('REA application analysis takes a directory or ASAR. Point it at the containing application directory.');
  const destination = path.resolve(output);
  await mkdir(path.dirname(destination), { recursive: true });
  const handle = await open(destination, 'wx');
  let bytes = 0; let diagnostic = '';
  const args = ['analyze-javascript-application', target.target, '--json'];
  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(executable, args, { stdio: ['ignore', handle.fd, 'pipe'], shell: false });
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('REA analysis exceeded 120 seconds.')); }, 120_000);
      child.stderr!.on('data', (chunk: Buffer) => { if (diagnostic.length < 8192) diagnostic += chunk.toString().slice(0, 8192 - diagnostic.length); });
      child.on('error', error => { clearTimeout(timer); reject(new Error(`Cannot start REA: ${error.message}. Install rea-agents separately or pass --rea-bin.`)); });
      child.on('close', code => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error(`REA exited ${code}: ${diagnostic}`)); });
    });
    bytes = (await handle.stat()).size;
    if (!bytes) throw new Error('REA returned no evidence.');
    // Streamed to disk: real application Evidence may be hundreds of MB.
    // This adapter records the provider output without inventing a graph mapping.
    return { status: 'recorded', provider: 'rea', executable, args, output: destination, bytes,
      normalizedByCarve: false, note: 'REA evidence is saved verbatim. An agent selects a module/symbol for the RECarve extraction plan.' };
  } catch (error) {
    await handle.close(); await unlink(destination); throw error;
  } finally { await handle.close().catch(() => {}); }
}
