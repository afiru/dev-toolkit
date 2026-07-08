import axios from 'axios';
import 'dotenv/config';

const fileKey = 'ZtR1sKuWUQec3ZJme9SAzZ';
const url = `https://api.figma.com/v1/files/${fileKey}`;

async function getNodes() {
    try {
        const res = await axios.get(url, {
            headers: {
                'X-Figma-Token': process.env.FIGMA_TOKEN
            }
        });

        // 文字列全体をJSON.stringifyするのではなく、JSONを直接見るか、一部だけ抽出
        console.log("ファイル名:", res.data.name);
        console.log("最初の子供ノードの数:", res.data.document.children.length);

        // 最初の子供ノードの構造だけ表示して確認する
        console.log("構造サンプル:", JSON.stringify(res.data.document.children[0], null, 2).substring(0, 2000));

    } catch (e) {
        console.error("エラー:", e.message);
    }
}
getNodes();