import fs from 'node:fs';

export function formatScss(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());

    const cats = {
        cl: [],
        bg: [],
        rd: []
    };
    lines.forEach(line => {
        if (line.includes('.cl_')) cats.cl.push(line);
        else if (line.includes('.bg_')) cats.bg.push(line);
        else if (line.includes('.rd_')) cats.rd.push(line);
    });

    const output = `/* Auto-generated from Figma */\n\n/* --- Text Colors --- */\n${cats.cl.join('\n')}\n\n/* --- Background Colors --- */\n${cats.bg.join('\n')}\n\n/* --- Border Radius --- */\n${cats.rd.join('\n')}`;
    fs.writeFileSync(filePath, output);
}