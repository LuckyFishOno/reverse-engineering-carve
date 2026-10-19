import bytes from 'bytes';

// The envelope is a source-owned Electron-style fixture. Its size formatter
// uses the real MIT-licensed bytes package, bundled into the shipped module.
const editorState = { windows: [], theme: 'dark' };
function startDesktopShell() {
  console.info('Desktop shell fixture initialized');
  editorState.windows.push('main');
}
startDesktopShell();

export function formatSize(value, options = {}) {
  if (!Number.isFinite(value)) throw new TypeError('size must be a finite number');
  return bytes.format(value, options);
}

export function openEditor() {
  return { windows: editorState.windows, platform: globalThis.navigator?.platform };
}
