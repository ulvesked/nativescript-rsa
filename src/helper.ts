export function stripPEMHeader(input: string) {
    let offset1 = input.indexOf('-----BEGIN') == -1 ? 0 : input.indexOf("\n");
    let offset2 = input.indexOf("-----END");
    return input.slice(offset1, offset2 == -1 ? input.length - offset1 : offset2);
}

export function chunkSplit(input: string, length: number = 64) {
    let result = [];
    for (let i = 0; i < input.length; i += 64) {
        result.push(input.substr(i, length));
    }
    return result.join("\r\n");
}