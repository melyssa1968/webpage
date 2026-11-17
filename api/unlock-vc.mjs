import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHandler } from '../lib/unlock-vc-gate.mjs';

let handler;
export default {
  async fetch(request) {
    if (!handler) {
      const demo = await readFile(path.join(process.cwd(), 'private/unlock-vc.html'), 'utf8');
      handler = createHandler({ demo });
    }
    return handler.fetch(request, process.env);
  },
};
