import fs from 'node:fs';
import axios from 'axios';
import 'dotenv/config';

export async function syncFigmaStyles(fileKey) {
    const url = `https://api.figma.com/v1/files/${fileKey}/styles`;
    const token = process.env.FIGMA_TOKEN;

    try {
        console.log('Fetching styles from Figma...');
        const res = await axios.get(url, {
            headers: {
                'X-Figma-Token': token
            }
        });
        const styles = res.data.meta.styles;

        let scssContent = '/* Auto-generated from Figma */\n\n';

        styles.forEach(s => {
            // ここでFigma上の名前をSCSSクラス名に変換 (例: Primary/Blue -> cl_primary_blue)
            const className = s.name.toLowerCase().replace(/\//g, '_');

            if (s.styleType === 'FILL') {
                // 仮の実装：ここではカラーコードを取得するロジックが必要
                scssContent += `.cl_${className} { color: /* 値の取得ロジックが必要 */; }\n`;
                scssContent += `.bg_${className} { background-color: /* 値の取得ロジックが必要 */; }\n`;
            }
        });

        fs.writeFileSync('./scss/Component/_colorS.scss', scssContent);
        console.log('Successfully updated _colorS.scss!');
    } catch (e) {
        console.error('Figma Sync Error:', e.message);
    }
}