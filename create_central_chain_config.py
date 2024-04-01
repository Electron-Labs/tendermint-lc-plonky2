import os
import yaml

chains_circuit_config = {}

chain_names = os.listdir("storage")
for i in range(len(chain_names)):
  chain_name = chain_names[i]
  with open(f"./tendermint-lc-plonky2/src/chain_config/{chain_name}.yaml") as stream:
      try:
          data = yaml.safe_load(stream)
          chains_circuit_config[chain_name] = {
                  "BLOCK_TIME_IN_SECOND": 10,
                  "TRUSTING_PERIOD_IN_SECOND": 1209600,
                  "SOURCE_RPC_ENDPOINT": data['RPC_ENDPOINT'],
                  "N_SIGNATURE_INDICES": data['N_SIGNATURE_INDICES'],
                  "SIGNATURE_INDICES_DOMAIN_SIZE": data['SIGNATURE_INDICES_DOMAIN_SIZE'],
                  "MIN_N_VALIDATORS": data['MIN_N_VALIDATORS'],
                  "MAX_N_VALIDATORS": data['MAX_N_VALIDATORS'],
              }
      except yaml.YAMLError as exc:
          print(exc)
with open('/home/ubuntu/tendermint-relayer-central-server/chains_config.yaml', 'w') as yaml_file:
    yaml.dump(chains_circuit_config, yaml_file, default_flow_style=False)
