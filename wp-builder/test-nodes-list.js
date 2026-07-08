// test-nodes-list.js
import axios from 'axios';
import 'dotenv/config';

const fileKey = 'DNwqWZtEcaLHAaFGsJxxmi';
const url = `https://api.figma.com/v1/files/${fileKey}`;

async function listNodes() {
    try {
        const res = await axios.get(url, {
            headers: {
                'X-Figma-Token': process.env.FIGMA_TOKEN
            }
        });

        // ファイル内の全てのノード名とIDをリストアップ
        res.data.document.children.forEach(page => {
            console.log(`ページ名: ${page.name} / ID: ${page.id}`);
            // さらにその中のフレームも確認
            if (page.children) {
                page.children.forEach(child => {
                    console.log(`  └ フレーム名: ${child.name} / ID: ${child.id}`);
                });
            }
        });
    } catch (e) {
        console.error(e.message);
    }
}
listNodes();