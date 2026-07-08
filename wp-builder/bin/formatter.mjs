import fs from 'node:fs';

const filePath = './scss/Component/_colorS.scss';
const content = fs.readFileSync(filePath, 'utf-8');
const lines = content.split('\n').filter(l => l.trim());

// 分類用ストレージ
const categories = {
    cl: [],
    bg: [],
    rd: []
};

// 行ごとに判定して振り分け
lines.forEach(line => {
    if (line.includes('.cl_')) categories.cl.push(line);
    else if (line.includes('.bg_')) categories.bg.push(line);
    else if (line.includes('.rd_')) categories.rd.push(line);
});

// 整形して出力
const output = `
/* --- Text Colors --- */
${categories.cl.join('\n')}

/* --- Background Colors --- */
${categories.bg.join('\n')}

/* --- Border Radius --- */
${categories.rd.join('\n')}
`;

fs.writeFileSync(filePath, output);
console.log('✅ _colorS.scss has been formatted by property!');