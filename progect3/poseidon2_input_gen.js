const fs = require('fs');

// 简单版本参数，须和电路保持一致
const rounds = 8;
const t = 3;
const rc = [
    [1,2,3],
    [4,5,6],
    [7,8,9],
    [10,11,12],
    [13,14,15],
    [16,17,18],
    [19,20,21],
    [22,23,24]
];
const mds = [
    [2,3,1],
    [1,2,3],
    [3,1,2]
];

// x^5计算
function pow5(x) {
    return x * x * x * x * x;
}

// 矩阵乘法 state = mds * state
function mdsMul(state) {
    let res = [0,0,0];
    for (let i=0; i<t; i++) {
        let sum = 0;
        for (let j=0; j<t; j++) {
            sum += mds[i][j] * state[j];
        }
        res[i] = sum;
    }
    return res;
}

// 计算poseidon2哈希
function poseidon2(preimage) {
    let state = preimage.slice();

    for (let r=0; r<rounds; r++) {
        // S-box
        for (let i=0; i<t; i++) {
            state[i] = pow5(state[i]) + rc[r][i];
        }
        // MDS矩阵乘法
        state = mdsMul(state);
    }

    return state[0];
}

// 随机生成3个输入元素
function randomPreimage() {
    return [
        Math.floor(Math.random()*1000),
        Math.floor(Math.random()*1000),
        Math.floor(Math.random()*1000)
    ];
}

// 主函数
function main() {
    const preimage = randomPreimage();
    const hash = poseidon2(preimage);

    const inputJson = {
        "hash": hash.toString(),
        "preimage": preimage.map(x => x.toString())
    };

    fs.writeFileSync("input.json", JSON.stringify(inputJson, null, 2));
    console.log("Generated input.json:");
    console.log(JSON.stringify(inputJson, null, 2));
}

main();
