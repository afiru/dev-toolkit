import axios from 'axios';

export async function fetchFigmaFile(fileKey, token) {
    const url = `https://api.figma.com/v1/files/${fileKey}`;
    const response = await axios.get(url, {
        headers: {
            'X-Figma-Token': token
        }
    });
    return response.data;
}
