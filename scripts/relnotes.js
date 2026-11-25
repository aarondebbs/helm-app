// Prints the release notes for one version from the console's change log: node scripts/relnotes.js 1.0.3
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync('internal/server/web/changelog.js', 'utf8').split("\nconst seenKey")[0];
const ctx = {}; vm.runInNewContext(src + '\nthis.C = CHANGELOG;', ctx);
const v = process.argv[2], e = ctx.C.find(x => x.v === v);
if (!e) { console.log('Helm ' + v); process.exit(0); }
const sec = (t, a) => a && a.length ? '### ' + t + '\n' + a.map(x => '- ' + x).join('\n') + '\n\n' : '';
process.stdout.write('## ' + e.title + '\n\n' + sec('New', e.new) + sec('Improved', e.better) + sec('Fixed', e.fixed));
