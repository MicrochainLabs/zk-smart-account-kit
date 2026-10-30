import { HardhatRuntimeEnvironment } from "hardhat/types";
import { createPublicClient, http, parseAbi, getContract, Address } from "viem";

/**
 * Get the EntryPoint address used by a Nexus account
 */
export async function getAccountEntryPoint(
    hre: HardhatRuntimeEnvironment,
    accountAddress: string
) {
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });

    console.log("\n🔍 Checking EntryPoint for Nexus account...");
    console.log("   Account:", accountAddress);
    console.log("   Network:", hre.network.name);

    // Query the account's entryPoint() view function
    const accountABI = parseAbi(["function entryPoint() external view returns (address)"]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi: accountABI,
        client: publicClient
    });

    try {
        const entryPointAddress = await accountContract.read.entryPoint() as Address;
        console.log("\n✅ EntryPoint Address:", entryPointAddress);

        // Identify which version it is
        const knownEntryPoints: Record<string, string> = {
            "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789": "v0.6.0",
            "0x0000000071727De22E5E9d8BAf0edAc6f37da032": "v0.7.0",
        };

        const version = knownEntryPoints[entryPointAddress] || "Unknown version";
        console.log("   Version:", version);

        console.log("\n⚠️  Important: The EntryPoint is IMMUTABLE and cannot be changed.");
        console.log("   This was set during account deployment and is hardcoded in the contract.");
        console.log("   To use a different EntryPoint (v0.8.0, v0.9.0, etc.), you would need to");
        console.log("   deploy a NEW account with that EntryPoint address.");

        return entryPointAddress;
    } catch (error) {
        console.error("\n❌ Error querying EntryPoint:", error);
        throw error;
    }
}
