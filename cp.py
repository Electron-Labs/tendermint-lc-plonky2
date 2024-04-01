import os
import shutil

# copy recursion circuit data to central-relayer repo
# chain_names = os.listdir("storage")
# for i in range(len(chain_names)):
#   shutil.copytree(
#     f"./storage/{chain_names[i]}/recursion_circuit/circuit_data",
#     f"/home/ubuntu/tendermint-relayer-central-server/chains_circuit_data/{chain_names[i]}"
#   )

# copy recursion proofs to aggregation-layer repo
chain_names = os.listdir("storage")
for i in range(len(chain_names)):
  shutil.copyfile(
    f"./storage/{chain_names[i]}/recursion_circuit/proof_data/proof_with_pis_xyz.json",
    f"/home/ubuntu/tendermint-relayer-central-server/aggregation-layer/chains_proof_data/1/{chain_names[i]}.json"
  )

  # print(os.curdir)
  # os.rename(f"{chain_names[i]}.yaml/current/file.foo", "path/to/new/destination/for/file.foo")