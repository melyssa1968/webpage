import { mkdir, rm, copyFile } from 'node:fs/promises';

await rm('public', { recursive: true, force: true });
await mkdir('public', { recursive: true });
// Only these public assets are published. Demo HTML stays in the server bundle.
for (const file of ['index.html', 'styles.css', 'favicon.svg']) {
  await copyFile(file, `public/${file}`);
}
