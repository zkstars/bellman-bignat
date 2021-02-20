const { ethers } = require("ethers");
const abi =[
    {
        "inputs": [
            {
                "components": [
                    {
                        "components": [
                            {
                                "internalType": "uint256",
                                "name": "X",
                                "type": "uint256"
                            },
                            {
                                "internalType": "uint256",
                                "name": "Y",
                                "type": "uint256"
                            }
                        ],
                        "internalType": "struct Pairing.G1Point",
                        "name": "a",
                        "type": "tuple"
                    },
                    {
                        "components": [
                            {
                                "internalType": "uint256[2]",
                                "name": "X",
                                "type": "uint256[2]"
                            },
                            {
                                "internalType": "uint256[2]",
                                "name": "Y",
                                "type": "uint256[2]"
                            }
                        ],
                        "internalType": "struct Pairing.G2Point",
                        "name": "b",
                        "type": "tuple"
                    },
                    {
                        "components": [
                            {
                                "internalType": "uint256",
                                "name": "X",
                                "type": "uint256"
                            },
                            {
                                "internalType": "uint256",
                                "name": "Y",
                                "type": "uint256"
                            }
                        ],
                        "internalType": "struct Pairing.G1Point",
                        "name": "c",
                        "type": "tuple"
                    }
                ],
                "internalType": "struct Verifier.Proof",
                "name": "proof",
                "type": "tuple"
            },
            {
                "internalType": "uint256[2]",
                "name": "input",
                "type": "uint256[2]"
            }
        ],
        "name": "verifyTx",
        "outputs": [
            {
                "internalType": "bool",
                "name": "r",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]



const   PublicRPC = "https://http-testnet.hecochain.com";
let provider = new ethers.providers.JsonRpcProvider(PublicRPC);


const verify_address = '0xAb4F0B64e9845fD3eEba2Af8623425740d5434A5'; // verifier contract address

let verifier = new ethers.Contract(verify_address,abi,provider)



async function getter(){

    var proof = {
        "proof": {
            "a": [
                "0x299817a80a2a5472a7768a7afaca490d430f1bd88696a94a43707033c428d364",
                "0x0f0af6ae43a20509c3a18eda6511202b1c826d953019f54de830e407f4438b27"
            ],
            "b": [
                [
                    "0x0ed66e878f02760803df82511b5ba116c82e067cdebae89f94196f967e7c700d",
                    "0x008f22514e3be53a369345b78403c3d9ddf0494ef55ba39b46c263e4490ad407"
                ],
                [
                    "0x024e33a346b9a2b0b902e6bb001b2a1acc281482c9d15a0e7b465be518ce9983",
                    "0x054d6a16ffcacfe9b8f4623335df358af9effb4be362134f0b953eeee84212d6"
                ]
            ],
            "c": [
                "0x2ebd3ba4b0b3def9b7492ccbccdaacffc629138285edf3c27f31cd1f0636efdd",
                "0x0558de0c89556577036c8c35c13b555f5abc28e41543d812bf09432c8f408143"
            ]
        },
        "inputs": [
            "0x0487cda17127481702dab6043cf863a65a8237a8e1e39eb750d9b77f8f9a6415",
            "0x02959bb6827969b25e04fed7ef95f8bb33d8fa6c473bcaa91894edd75dc8d80a"
        ]
    }
    var res = await verifier.verifyTx(proof.proof,proof.inputs);
    console.log(res);

}

getter();
