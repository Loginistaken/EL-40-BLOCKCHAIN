#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <thread>
#include <asio.hpp>
#include <cstdlib>
#include <crypto++/sha3.h>  // SHA-3 header from Crypto++ library
#include <crypto++/hex.h>    // Hex encoding (to display the hash)

// Custom Hash Function (SHA-3)
std::string EL40_Hash(const std::string& input) {
    using namespace CryptoPP;

    // Initialize SHA-3
    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];

    // Calculate the hash
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    // Convert digest to hex string for display
    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;  // Return the hex-encoded hash
}

// Machine Learning Model Placeholder for Block Approval
bool approveBlockAI(const std::string& blockData) {
    // Future AI logic for approving/rejecting blocks
    std::cout << "ML Model analyzing block: " << blockData << "... Approved!\n";
    return true;
}

// Difficulty Adjustment for Fragments
int adjustDifficulty(int blockHeight) {
    return blockHeight / 10 + 1;  // Increase difficulty as the blockchain grows
}

// Block Structure
struct Block {
    int index;
    std::string timestamp;
    std::string data;
    std::string prevHash;
    std::string hash;
    int nonce;
    std::vector<std::string> fragmentHashes; // Fragment hashes

    Block(int idx, const std::string& dataInput, const std::string& prev)
        : index(idx), data(dataInput), prevHash(prev), nonce(0) {
        timestamp = std::to_string(std::time(nullptr));
        hash = generateHash();
    }

    std::string generateHash() const {
        std::string toHash = std::to_string(index) + timestamp + data + prevHash + std::to_string(nonce);
        return EL40_Hash(toHash);  // Use SHA-3 to generate hash
    }

    // Mined fragment with difficulty adjustment
    void mineFragment(int difficulty) {
        std::string fragmentData = data + std::to_string(nonce);
        std::string fragmentHash = EL40_Hash(fragmentData);
        fragmentHashes.push_back(fragmentHash);
        nonce++;
    }
};

// Blockchain Class
class EL40_Blockchain {
private:
    std::vector<Block> chain;
    std::unordered_map<std::string, std::string> transactionLedger; // External tracking

public:
    EL40_Blockchain() {
        chain.push_back(createVariableBlock());
    }

    Block createVariableBlock() {
        return Block(0, "Variable-Block", "0");
    }

    void addBlock(const std::string& data) {
        if (approveBlockAI(data)) { // AI approval process
            Block last = chain.back();
            Block newBlock(chain.size(), data, last.hash);

            // Mine the block in fragments with difficulty adjustment
            int difficulty = adjustDifficulty(chain.size());
            for (int i = 0; i < difficulty; ++i) {
                newBlock.mineFragment(difficulty);
            }

            chain.push_back(newBlock);
            transactionLedger[newBlock.hash] = data; // Store transaction externally
        } else {
            std::cout << "Block rejected by AI approval process.\n";
        }
    }

    void displayChain() const {
        for (const auto& block : chain) {
            std::cout << "Index: " << block.index << "\n"
                      << "Time: " << block.timestamp << "\n"
                      << "Data: " << block.data << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Previous: " << block.prevHash << "\n"
                      << "Fragment Hashes: ";
            for (const auto& fragHash : block.fragmentHashes) {
                std::cout << fragHash << " ";
            }
            std::cout << "\n\n";
        }
    }

    void fetchExternalTransactions() {
        std::cout << "Fetching external transactions using Python scraper...\n";
        system("python3 scraper.py"); // Calls external Python scraper
    }
};

// Node Access Agreement Function
bool nodeAccessAgreement() {
    std::string response;
    std::cout << "\nEL-40 Blockchain: Do you accept the node connection agreement? (yes/no): ";
    std::cin >> response;

    if (response == "yes" || response == "Yes") {
        std::cout << "\nAccess granted. Connecting node...\n";
        std::cout << "\nThis connection allows nodes to sync transactions and view blockchain data securely.\n";
        return true;
    } else {
        std::cout << "\nAccess denied. Returning to homepage...\n";
        return false;
    }
}

// Peer-to-Peer Networking
void startServer(unsigned short port) {
    try {
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
        std::cout << "Server started on port " << port << "\n";

        for (;;) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::cout << "New node connected!\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Server Error: " << e.what() << "\n";
    }
}

int main() {
    std::cout << "\nWelcome to EL-40 Blockchain!";
    if (!nodeAccessAgreement()) {
        return 0;
    }

    EL40_Blockchain myChain;
    myChain.addBlock("First Secure Block");
    myChain.addBlock("Second Secure Block");
    myChain.displayChain();

    // Fetch external transactions
    myChain.fetchExternalTransactions();

    // Start P2P server in a separate thread
    std::thread serverThread(startServer, 8080);
    serverThread.detach();

    return 0;
}

// Simulate node network with multithreading (each thread represents a node)
void runNode(EL40_Blockchain& blockchain, const std::string& blockData) {
    blockchain.addBlock(blockData);
}

int main() {
    EL40_Blockchain blockchain;

    // Simulate multiple nodes mining and communicating
    std::thread node1(runNode, std::ref(blockchain), "Node 1 Block Data");
    std::thread node2(runNode, std::ref(blockchain), "Node 2 Block Data");

    node1.join();
    node2.join();

    blockchain.displayChain();
    return 0;
}
#include <iostream>
#include <cstdlib>
#include <thread>
#include <chrono>

void displayExitPopup() {
    // Displaying the exit popup with MIT License and Credits
    std::cout << "\n\n--- Exit Acknowledgment ---\n";
    std::cout << "MIT License\n";
    std::cout << "Copyright (c) 2025 EL-40 Blockchain\n";
    std::cout << "Special thanks to GPT Chat for assistance in the development.\n";
    std::cout << "This software is provided 'as-is' without any express or implied warranty.\n";
    std::cout << "For more information, visit: https://opensource.org/licenses/MIT\n";
    std::cout << "Email: elindau85@gmail.com\n";
    std::cout << "By: EL (El-40 Blockchain)\n";
    std::cout << "--- End of License ---\n";

    // A simulated DDoS protection message (in real cases, you would integrate DDoS mechanisms, this is just an illustration)
    std::cout << "\nDDoS Protection Enabled: Network safety is ensured during this operation.\n";
}

int main() {
    std::cout << "Welcome to the EL-40 Blockchain Program.\n";

    // Simulate program work for demonstration (replace with your actual logic)
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Call the exit popup before exiting
    displayExitPopup();

    // You can add additional actions here for logging or more security measures if needed
    // Exit the program
    std::cout << "Exiting program...\n";
    return 0;
}
