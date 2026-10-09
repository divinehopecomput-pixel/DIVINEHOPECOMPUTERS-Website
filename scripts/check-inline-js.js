const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const files = ['public/index.html', 'public/admin.html'];
let checked = 0;
for (const file of files) {
  const html = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];
  if (!scripts.length) throw new Error('No inline script found in ' + file);
  scripts.forEach((match, index) => {
    new vm.Script(match[1], { filename: file + ':script-' + (index + 1) });
    checked++;
  });
}
console.log('JavaScript syntax OK: server.js is checked by npm script; ' + checked + ' inline browser scripts parsed.');
