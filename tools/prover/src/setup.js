/**
 * Prover Setup Script
 * Downloads or links circuit artifacts for proof generation
 */

import { readFileSync, existsSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "../../..");
const CIRCUIT_DIR = join(PROJECT_ROOT, "circuits/testdata");

/**
 * Check if required circuit files exist
 */
export function checkCircuitFiles() {
    const required = [
        "vote.r1cs",
        "vote.sym",
        "vote_js/vote.wasm",
        "vote_final.zkey",
        "verification_key.json"
    ];

    console.log("Checking circuit files...\n");

    let allExist = true;
    for (const file of required) {
        const path = join(CIRCUIT_DIR, file);
        const exists = existsSync(path);
        console.log(`  ${exists ? "✅" : "❌"} ${file}`);
        if (!exists) {
            allExist = false;
        }
    }

    return allExist;
}

/**
 * Print setup instructions
 */
export function printSetupInstructions() {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║           ZK Vote Proof Generator - Setup Instructions        ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  1. Compile the circuit (if not done):                         ║
║     cd ../../circuits                                         ║
║     circom src/spm/vote.circom --r1cs --wasm --sym \\          ║
║       -o testdata -l ../node_modules                          ║
║                                                                ║
║  2. Run trusted setup:                                         ║
║     cd ../..                                                  ║
║     make setup                                                ║
║     make zkey                                                 ║
║                                                                ║
║  3. Generate proofs:                                           ║
║     cd tools/prover                                            ║
║     node src/index.js prove 1                                  ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
`);
}

/**
 * Main setup function
 */
export function setup() {
    console.log("ZK Vote Proof Generator Setup\n");

    const filesExist = checkCircuitFiles();

    if (!filesExist) {
        console.log("\n⚠️  Some circuit files are missing!");
        printSetupInstructions();
        return false;
    }

    console.log("\n✅ All circuit files are ready!");
    console.log("\nYou can now generate proofs:");
    console.log("  node src/index.js prove 1");

    return true;
}

// Run setup if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    setup();
}
