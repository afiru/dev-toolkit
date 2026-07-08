import axios from 'axios';
import 'dotenv/config';

// .env から読み込む設定
const fileKey = 'kQ01ppkayPXXUyd5pMefrB';
const url = `https://api.figma.com/v1/files/${fileKey}/styles`;

async function getStyles() {
    try {
        console.log('Figmaに接続中...');
        const res = await axios.get(url, {
            headers: {
                'X-Figma-Token': process.env.FIGMA_TOKEN
            }
        });
        // 取得したデータをそのまま表示する
        console.log(JSON.stringify(res.data, null, 2));
    } catch (e) {
        console.error("エラー発生！:", e.message);
    }
}
getStyles();