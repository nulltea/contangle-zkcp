const wasm_tester = require("circom_tester").wasm;
const ff = require("ffjavascript");
exports.p = ff.Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const Fr = new ff.F1Field(exports.p);

describe("circom circuits", () => {
	test("hash", async () => {
		let circuit = await wasm_tester("hash.circom");
		await circuit.loadConstraints();

		const inputs = {
			"plaintext": [0]
		};
		const witness = await circuit.calculateWitness(inputs, true);
		let hash = BigInt(witness[1]);
		console.log(hash.toString('16'));
	});
});


