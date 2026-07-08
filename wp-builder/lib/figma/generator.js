// lib/figma/generator.js

function toHex(c) {
    return Math.round(c * 255).toString(16).padStart(2, '0');
}

export function parseNodeToScss(node) {
    let scss = '';

    // 色データの取得とクラス生成
    if (node.fills && node.fills.length > 0 && node.fills[0].type === 'SOLID') {
        const {
            r,
            g,
            b
        } = node.fills[0].color;
        const hex = `${toHex(r)}${toHex(g)}${toHex(b)}`; // #なしの文字列

        scss += `.cl_${hex} { color: #${hex}; }\n`;
        scss += `.bg_${hex} { background-color: #${hex}; }\n`;
    }

    // 角丸データの取得とクラス生成
    if (node.rectangleCornerRadii) {
        // 全ての角が同じならシンプルに、異なれば個別指定にする
        const radii = node.rectangleCornerRadii.map(n => Math.round(n)).join('_');
        scss += `.rd_${radii} { border-radius: ${radii.replace(/_/g, 'px ')}px; }\n`;
    }

    return scss;
}