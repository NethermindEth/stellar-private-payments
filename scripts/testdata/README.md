Test data for `scripts/deploy.sh`

This folder contains sample inputs you can pass to the deploy script. The values
here are placeholders and will not verify real proofs.

Files:
- `vk.json`: Dummy VerificationKeyBytes payload for the circom verifier constructor.

Details:
- `vk.json` uses the `VerificationKeyBytes` shape expected by the verifier
  contract: `alpha`, `beta`, `gamma`, `delta`, and `ic` as hex strings. The
  dummy values are short and do not represent a real Groth16 verifying key.
- The deploy script can also accept snarkjs-style `vk.json` files (keys like
  `vk_alpha_1`, `vk_beta_2`, `vk_gamma_2`, `vk_delta_2`, `IC`) and will convert
  them to the required `VerificationKeyBytes` format at runtime.
- If you have a real verifying key, replace each field with the byte-encoded
  value produced by your key generation flow.
- This data is only intended for testing script wiring, not for proof validation.

Example usage:

  scripts/deploy.sh futurenet \
    --deployer alice \
    --token CB... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000 \
    --vk-file scripts/testdata/vk.json

Notes:
- If `--token` is omitted, the script defaults to the Soroban native XLM token
  contract for the selected network.
- Replace `alice` with a real Stellar identity (or pass a secret key).
- For a real deployment, replace `vk.json` with the actual verification key JSON.
- Deployment output is written to `scripts/deployments.json`.
