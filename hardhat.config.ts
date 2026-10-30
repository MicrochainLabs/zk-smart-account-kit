import { HardhatUserConfig } from "hardhat/types";
import { task, vars } from "hardhat/config";
import "hardhat-deploy";
import "@nomicfoundation/hardhat-toolbox-viem";
import "@nomicfoundation/hardhat-ignition";
import "@nomicfoundation/hardhat-ignition-viem";
import "@nomicfoundation/hardhat-foundry";

import { DeterministicDeploymentInfo } from "hardhat-deploy/dist/types";
import { getSingletonFactoryInfo } from "@safe-global/safe-singleton-factory";

import { getAccountEntryPoint } from "./zknexus/zknexus";
import { computeZKLabeledNexusAddress, getZKLabeledNexusConfig, checkZKLabeledNexusAccount, createZKLabeledNexusAccount, sendZKLabeledNexusUserOp, computeLabeledUserOpHash, createZKLabeledSignerFactoryContract, LabeledSigner, LabeledEntry } from "./zknexus/zklabeled";
import { computeZKLabeledScopeNexusAddress, getZKLabeledScopeNexusConfig, checkZKLabeledScopeNexusAccount, createZKLabeledScopeNexusAccount, sendZKLabeledScopeNexusUserOp, computeLabeledScopeUserOpHash, createZKLabeledSignerScopeFactoryContract, createZKLabeledSignerScopeValidatorRedeploy, LabeledScopeRule, ParamConstraint } from "./zknexus/zklabeledscope";

const deterministicDeployment = (network: string): DeterministicDeploymentInfo => {
    const info = getSingletonFactoryInfo(parseInt(network));
    if (!info) {
        throw new Error(`
        Safe factory not found for network ${network}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
        For more information, see https://github.com/safe-global/safe-contracts#replay-protection-eip-155
      `);
    }
    return {
        factory: info.address,
        deployer: info.signerAddress,
        funding: (BigInt(info.gasLimit) * BigInt(info.gasPrice)).toString(),
        signedTx: info.transaction,
    };
};

task("createZKLabeledFactory", "Deploy ZKLabeledSignerValidator + ZKLabeledSignerValidatorFactory and all supporting verifiers")
    .addParam("mainsigners", "JSON array of {label,address} — the org-wide master signer list")
    .addParam("owner", "Address authorised to rotate mainSignersRoot")
    .setAction(async (taskArgs, hre) => createZKLabeledSignerFactoryContract(
        hre,
        JSON.parse(taskArgs.mainsigners) as LabeledSigner[],
        taskArgs.owner
    ));


// ZK Labeled Signer Nexus tasks
// ---------------------------------------------------------------------------
// Structured inputs (subsetSigners, mainSigners, contacts, protocols,
// registryEntries) are passed as JSON strings on the command line.
// Example:
//   --subsetSigners '[{"label":"alice","address":"0x..."}]'
// ---------------------------------------------------------------------------

task("createZKLabeledNexusAccount", "Create a Nexus account with ZKLabeledSignerValidator")
    .addParam("factoryaddress", "ZKLabeledSignerValidatorFactory contract address")
    .addParam("validatoraddress", "ZKLabeledSignerValidator contract address")
    .addParam("mainsignersroot", "Factory's current mainSignersRoot (bytes32 hex)")
    .addParam("mainsigners", "JSON array of {label,address} for the full org-wide signer list")
    .addParam("subsetsigners", "JSON array of {label,address} for this account's signers (max 5)")
    .addParam("contacts", "JSON array of {label,address} for the initial contact book")
    .addParam("protocols", "JSON array of {label,address} for the initial protocol list")
    .setAction(async (taskArgs, hre) => createZKLabeledNexusAccount(
        hre,
        JSON.parse(taskArgs.mainsigners)   as LabeledSigner[],
        JSON.parse(taskArgs.subsetsigners) as LabeledSigner[],
        JSON.parse(taskArgs.contacts)      as LabeledEntry[],
        JSON.parse(taskArgs.protocols)     as LabeledEntry[],
        taskArgs.validatoraddress,
        taskArgs.factoryaddress,
        taskArgs.mainsignersroot
    ));

task("sendZKLabeledNexusUserOp", "Send a UserOperation using a ZK Labeled Signer Nexus account")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "ZKLabeledSignerValidator contract address")
    .addOptionalParam("entrypoint", "EntryPoint contract address (auto-detected if omitted)", "")
    .addParam("to", "Call target address")
    .addParam("value", "Value in wei (or decimal POL, e.g. \"0.01\")")
    .addParam("data", "Call data (hex)")
    .addParam("signature", "Signer's ECDSA signature over the UserOp hash (see computeLabeledUserOpHash)")
    .addParam("userophash", "The UserOp hash that --signature was produced over")
    .addParam("signerlabel", "Signer's label name in the signersRoot")
    .addParam("subsetsigners", "JSON array of {label,address} — all signers in the account's subset")
    .addParam("registrytype", "\"contacts\" or \"protocols\" — which registry to prove against")
    .addParam("registryentries", "JSON array of {label,address} for the chosen registry")
    .addParam("destlabel", "Destination's label name in the registry")
    .setAction(async (taskArgs, hre) => sendZKLabeledNexusUserOp(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.entrypoint,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data,
        taskArgs.signature,
        taskArgs.userophash,
        taskArgs.signerlabel,
        JSON.parse(taskArgs.subsetsigners)    as LabeledSigner[],
        taskArgs.registrytype as "contacts" | "protocols",
        JSON.parse(taskArgs.registryentries)  as LabeledEntry[],
        taskArgs.destlabel
    ));

task("computeZKLabeledNexusAddress", "Predict the CREATE2 address of a ZK Labeled Signer Nexus account")
    .addParam("factory", "ZKLabeledSignerValidatorFactory contract address")
    .addParam("validator", "ZKLabeledSignerValidator contract address")
    .addParam("subsetsignersroot", "Subset signers root (bytes32 hex)")
    .addParam("contactsroot", "Contacts root (bytes32 hex)")
    .addParam("protocolsroot", "Protocols root (bytes32 hex)")
    .addOptionalParam("index", "Account index", "0")
    .setAction(async (taskArgs, hre) => computeZKLabeledNexusAddress(
        hre,
        taskArgs.factory,
        taskArgs.validator,
        taskArgs.subsetsignersroot,
        taskArgs.contactsroot,
        taskArgs.protocolsroot,
        taskArgs.index
    ));

task("getZKLabeledNexusConfig", "Read the ZKLabeledSignerValidator roots for a Nexus account")
    .addParam("validator", "ZKLabeledSignerValidator contract address")
    .addParam("account", "Nexus account address")
    .setAction(async (taskArgs, hre) => getZKLabeledNexusConfig(
        hre,
        taskArgs.validator,
        taskArgs.account
    ));

task("checkZKLabeledNexusAccount", "Print a status report for a ZK Labeled Signer Nexus account")
    .addParam("account", "Nexus account address")
    .addParam("validator", "ZKLabeledSignerValidator contract address")
    .setAction(async (taskArgs, hre) => checkZKLabeledNexusAccount(
        hre,
        taskArgs.account,
        taskArgs.validator
    ));

task("computeLabeledUserOpHash", "Compute the UserOp hash for a labeled signer account (without proving)")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "ZKLabeledSignerValidator contract address")
    .addParam("to", "Call target address")
    .addParam("value", "Value in wei (or decimal POL)")
    .addParam("data", "Call data (hex)")
    .setAction(async (taskArgs, hre) => computeLabeledUserOpHash(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data
    ));


// ZK Labeled Signer + Scope Nexus tasks
// ---------------------------------------------------------------------------
// Same conventions as the ZK Labeled Signer Nexus tasks above, but the
// contacts/protocols registries are replaced by a single unified scope tree
// (--scoperules), whose entries are {label,target,selectorField,valueMax,
// constraints} — see zknexus/zklabeledscope.ts's LabeledScopeRule type.
// Example:
//   --scoperules '[{"label":"alice","target":"0x...","selectorField":"0","valueMax":"340282366920938463463374607431768211455","constraints":[{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"}]}]'
// ---------------------------------------------------------------------------

task("createZKLabeledScopeFactory", "Deploy ZKLabeledSignerScopeValidator + ZKLabeledSignerScopeValidatorFactory and all supporting verifiers")
    .addParam("mainsigners", "JSON array of {label,address} — the org-wide master signer list")
    .addParam("owner", "Address authorised to rotate mainSignersRoot")
    .setAction(async (taskArgs, hre) => createZKLabeledSignerScopeFactoryContract(
        hre,
        JSON.parse(taskArgs.mainsigners) as LabeledSigner[],
        taskArgs.owner
    ));

task("redeployZKLabeledScopeValidator", "Redeploy ONLY ZKLabeledSignerScopeValidator + ZKLabeledSignerScopeValidatorFactory, reusing the existing HonkVerifiers/ERC-8039 adapters")
    .addParam("mainsignersroot", "Existing factory's mainSignersRoot (bytes32 hex) — reused as-is unless rotating it")
    .addParam("owner", "Address authorised to rotate mainSignersRoot")
    .setAction(async (taskArgs, hre) => createZKLabeledSignerScopeValidatorRedeploy(
        hre,
        taskArgs.mainsignersroot,
        taskArgs.owner
    ));

task("createZKLabeledScopeNexusAccount", "Create a Nexus account with ZKLabeledSignerScopeValidator")
    .addParam("factoryaddress", "ZKLabeledSignerScopeValidatorFactory contract address")
    .addParam("validatoraddress", "ZKLabeledSignerScopeValidator contract address")
    .addParam("mainsignersroot", "Factory's current mainSignersRoot (bytes32 hex)")
    .addParam("mainsigners", "JSON array of {label,address} for the full org-wide signer list")
    .addParam("subsetsigners", "JSON array of {label,address} for this account's signers (max 5)")
    .addParam("scoperules", "JSON array of LabeledScopeRule for the initial unified scope tree")
    .setAction(async (taskArgs, hre) => createZKLabeledScopeNexusAccount(
        hre,
        JSON.parse(taskArgs.mainsigners)   as LabeledSigner[],
        JSON.parse(taskArgs.subsetsigners) as LabeledSigner[],
        JSON.parse(taskArgs.scoperules)    as LabeledScopeRule[],
        taskArgs.validatoraddress,
        taskArgs.factoryaddress,
        taskArgs.mainsignersroot
    ));

task("sendZKLabeledScopeNexusUserOp", "Send a UserOperation using a ZK Labeled Signer + Scope Nexus account")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "ZKLabeledSignerScopeValidator contract address")
    .addOptionalParam("entrypoint", "EntryPoint contract address (auto-detected if omitted)", "")
    .addParam("to", "Call target address")
    .addParam("value", "Value in wei (or decimal POL, e.g. \"0.01\")")
    .addParam("data", "Call data (hex)")
    .addParam("signature", "Signer's ECDSA signature over the UserOp hash (see computeLabeledScopeUserOpHash)")
    .addParam("userophash", "The UserOp hash that --signature was produced over")
    .addParam("signerlabel", "Signer's label name in the signersRoot")
    .addParam("subsetsigners", "JSON array of {label,address} — all signers in the account's subset")
    .addParam("destlabel", "Destination's label name in the unified scope tree")
    .addParam("rule", "JSON LabeledScopeRule this call is proven against")
    .addParam("scoperules", "JSON array of all LabeledScopeRule entries (to rebuild scopeRoot's tree)")
    .setAction(async (taskArgs, hre) => sendZKLabeledScopeNexusUserOp(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.entrypoint,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data,
        taskArgs.signature,
        taskArgs.userophash,
        taskArgs.signerlabel,
        JSON.parse(taskArgs.subsetsigners) as LabeledSigner[],
        taskArgs.destlabel,
        JSON.parse(taskArgs.rule)          as LabeledScopeRule,
        JSON.parse(taskArgs.scoperules)    as LabeledScopeRule[]
    ));

task("computeZKLabeledScopeNexusAddress", "Predict the CREATE2 address of a ZK Labeled Signer + Scope Nexus account")
    .addParam("factory", "ZKLabeledSignerScopeValidatorFactory contract address")
    .addParam("validator", "ZKLabeledSignerScopeValidator contract address")
    .addParam("subsetsignersroot", "Subset signers root (bytes32 hex)")
    .addParam("scoperoot", "Unified scope tree root (bytes32 hex)")
    .addOptionalParam("index", "Account index", "0")
    .setAction(async (taskArgs, hre) => computeZKLabeledScopeNexusAddress(
        hre,
        taskArgs.factory,
        taskArgs.validator,
        taskArgs.subsetsignersroot,
        taskArgs.scoperoot,
        taskArgs.index
    ));

task("getZKLabeledScopeNexusConfig", "Read the ZKLabeledSignerScopeValidator roots for a Nexus account")
    .addParam("validator", "ZKLabeledSignerScopeValidator contract address")
    .addParam("account", "Nexus account address")
    .setAction(async (taskArgs, hre) => getZKLabeledScopeNexusConfig(
        hre,
        taskArgs.validator,
        taskArgs.account
    ));

task("checkZKLabeledScopeNexusAccount", "Print a status report for a ZK Labeled Signer + Scope Nexus account")
    .addParam("account", "Nexus account address")
    .addParam("validator", "ZKLabeledSignerScopeValidator contract address")
    .setAction(async (taskArgs, hre) => checkZKLabeledScopeNexusAccount(
        hre,
        taskArgs.account,
        taskArgs.validator
    ));

task("computeLabeledScopeUserOpHash", "Compute the UserOp hash for a labeled signer + scope account (without proving)")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "ZKLabeledSignerScopeValidator contract address")
    .addParam("to", "Call target address")
    .addParam("value", "Value in wei (or decimal POL)")
    .addParam("data", "Call data (hex)")
    .setAction(async (taskArgs, hre) => computeLabeledScopeUserOpHash(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data
    ));


//Utility tasks
task("getAccountEntryPoint", "Get the EntryPoint address used by a Nexus account")
    .addParam("account", "The Nexus account address")
    .setAction(async (taskArgs, hre) => getAccountEntryPoint(hre, taskArgs.account));

const getAccounts = function(): string[] {
    let accounts = [];
    accounts.push(vars.get("DEPLOYER_PRIVATE_KEY"));
    accounts.push(vars.get("SAFE_OWNER_PRIVATE_KEY"));
    return accounts;
}

const config: HardhatUserConfig = {
    paths: {
        sources: "./contracts",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    solidity: {
        compilers: [
            {
                version: "0.8.29",
                settings: {
                    //viaIR: true,
                    optimizer: {
                        enabled: true,
                        runs: 20
                    },
                    evmVersion: "cancun"
                }
            },
            {
                version: "0.8.27",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    },
                    evmVersion: "cancun"
                }
            },
            {
                version: "0.8.20",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    },
                    evmVersion: "paris"
                }
            }
        ]
    },
    namedAccounts: {
        deployer: {
            default: 0,
        },
        users: {
            default: 1,
        },
    },
    networks: {
        mainnet: {
            url: "http://192.168.1.4:8545",
            accounts: getAccounts(),
        },
        localhost: {
            url: "http://127.0.0.1:8545",
        },
        gnosis: {
            url: "https://gnosis.drpc.org",
            accounts: getAccounts(),
        },
        bsc: {
            url: "https://bsc-dataseed.binance.org/",
            accounts: getAccounts(),
        },
        polygon: {
            url: vars.get("POLYGON_RPC"),
            accounts: getAccounts(),
        },
        polygonAmoy: {
            url: "https://rpc-amoy.polygon.technology",
            accounts: getAccounts(),
            chainId: 80002,
        },
        sepolia: {
            url: "https://ethereum-sepolia-rpc.publicnode.com",
            accounts: getAccounts(),
        },
        telos: {
             url: "https://mainnet-asia.telos.net/evm",
             accounts: getAccounts(),
        },
        arbitrum: {
            url: "https://1rpc.io/arb",
            accounts: getAccounts(),
        },
        optimism: {
            url: "https://1rpc.io/op",
            accounts: getAccounts(),
        },
        buildbear: {
            url:  "https://rpc.buildbear.io/1kx",
            accounts: getAccounts(),
        },
        base: {
            url: "https://base.rpc.subquery.network/public",
            accounts: getAccounts(),
            initialBaseFeePerGas: 5000000000, // 5 gwei
            gasPrice: 25000000000, // 25 gwei (base fee + priority fee)
        },
        scroll: {
            url: "https://scroll.drpc.org",
            accounts: getAccounts(),
        }
    },
    etherscan: {
        customChains: [
         {
            network: "gnosis",
            chainId: 100,
            urls: {
              // 3) Select to what explorer verify the contracts
              // Gnosisscan
              apiURL: "https://api.gnosisscan.io/api",
              browserURL: "https://gnosisscan.io/",
            },
          },
          {
            network: "bsc",
            chainId: 56,
            urls: {
              apiURL: "https://api.bscscan.com/api",
              browserURL: "https://bscscan.com/",
            },
          },
          {
            network: "polygon",
            chainId: 137,
            urls: {
              apiURL: "https://api.etherscan.io/v2/api?chainid=137",
              browserURL: "https://polygonscan.com/",
            },
          },
          {
            network: "scroll",
            chainId: 534352,
            urls: {
              apiURL: "https://api.scrollscan.com/api",
              browserURL: "https://scrollscan.com/",
            },
          }
        ],
        apiKey: {
            gnosis: vars.get("GNOSISSCAN_API_KEY", ""),
            sepolia: vars.get("ETHERSCAN_API_KEY", ""),
            mainnet: vars.get("ETHERSCAN_API_KEY", ""),
            bsc: vars.get("BSCSCAN_API_KEY", ""),
            polygon: "JGD5ZUUBHE8CUXPNKZASVQPHRGBMB7A5XV",
            arbitrumOne: vars.get("ARBISCAN_API_KEY", ""),
            optimisticEthereum: vars.get("OPTIMISTIC_API_KEY", ""),
            scroll: vars.get("SCROLLSCAN_API_KEY", ""),
            base: vars.get("BASESCAN_API_KEY", ""),
        },
    },
    ignition: {
        strategyConfig: {
            create2: {
                // salt: "0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD" + "00" + "69eb570cb274b0ebea0271",
                salt: "0x00000000000000000000000000000000000000000069eb570cb274b0ebea0275",
            }
        }
    },
    mocha: {
        timeout: 100000000
    },
    deterministicDeployment,
};

export default config;
