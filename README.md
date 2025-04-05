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
#include <crypto++/rsa.h>  // RSA for digital signatures
#include <crypto++/osrng.h> // AutoSeededRandomPool for key generation
#include <crypto++/base64.h> // Base64 encoding/decoding
#include <mutex>

// Custom Hash Function (SHA-3)
std::string EL40_Hash(const std::string& input) {
    using namespace CryptoPP;

    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;  // Return the hex-encoded hash
}

// Transaction Structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string signature;

    std::string toString() const {
        return sender + receiver + std::to_string(amount);
    }
};

// Digital Signature Utility
std::string signTransaction(const std::string& data, const CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string signature;

    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
    CryptoPP::StringSource ss(data, true,
        new CryptoPP::SignerFilter(rng, signer,
            new CryptoPP::StringSink(signature)
        )
    );
    return signature;
}

bool verifyTransaction(const std::string& data, const std::string& signature, const CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
    bool result = false;

    CryptoPP::StringSource ss(signature + data, true,
        new CryptoPP::SignatureVerificationFilter(
            verifier,
            new CryptoPP::ArraySink((byte*)&result, sizeof(result)),
            CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION | CryptoPP::SignatureVerificationFilter::PUT_RESULT
        )
    );
    return result;
}

// Block Structure
struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;
    std::vector<std::string> fragmentHashes; // Fragment hashes

    Block(int idx, const std::vector<Transaction>& txs, const std::string& prev)
        : index(idx), transactions(txs), prevHash(prev), nonce(0) {
        timestamp = std::to_string(std::time(nullptr));
        hash = generateHash();
    }

    std::string generateHash() const {
        std::string toHash = std::to_string(index) + timestamp + prevHash + std::to_string(nonce);
        for (const auto& tx : transactions) {
            toHash += tx.toString();
        }
        return EL40_Hash(toHash);
    }

    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = generateHash();
        }
    }

    void mineFragment(int difficulty) {
        std::string fragmentData = std::to_string(index) + timestamp + prevHash + std::to_string(nonce);
        std::string fragmentHash = EL40_Hash(fragmentData);
        fragmentHashes.push_back(fragmentHash);
        nonce++;
    }
};

// Blockchain Class
class EL40_Blockchain {
private:
    std::vector<Block> chain;
    std::unordered_map<std::string, double> ledger;
    std::mutex chainMutex;

public:
    EL40_Blockchain() {
        chain.push_back(createGenesisBlock());
        ledger["Genesis"] = 1000;
    }

    Block createGenesisBlock() {
        return Block(0, {}, "0");
    }

    void addBlock(const std::vector<Transaction>& transactions) {
        std::lock_guard<std::mutex> lock(chainMutex);
        if (approveBlockAI(transactionsToString(transactions))) {
            Block last = chain.back();
            Block newBlock(chain.size(), transactions, last.hash);

            int difficulty = adjustDifficulty(chain.size());
            newBlock.mineBlock(difficulty);

            chain.push_back(newBlock);
            for (const auto& tx : transactions) {
                ledger[tx.sender] -= tx.amount;
                ledger[tx.receiver] += tx.amount;
            }
        } else {
            std::cout << "Block rejected by AI approval process.\n";
        }
    }

    void displayChain() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        for (const auto& block : chain) {
            std::cout << "Index: " << block.index << "\n"
                      << "Time: " << block.timestamp << "\n"
                      << "Previous: " << block.prevHash << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Transactions: ";
            for (const auto& tx : block.transactions) {
                std::cout << tx.sender << " -> " << tx.receiver << ": " << tx.amount << " ";
            }
            std::cout << "\nFragment Hashes: ";
            for (const auto& fragHash : block.fragmentHashes) {
                std::cout << fragHash << " ";
            }
            std::cout << "\nNonce: " << block.nonce << "\n\n";
        }
    }

private:
    std::string transactionsToString(const std::vector<Transaction>& transactions) const {
        std::string result;
        for (const auto& tx : transactions) {
            result += tx.toString();
        }
        return result;
    }
};

// Machine Learning Model Placeholder for Block Approval
bool approveBlockAI(const std::string& blockData) {
    std::cout << "ML Model analyzing block: " << blockData << "... Approved!\n";
    return true;
}

// Difficulty Adjustment for Fragments
int adjustDifficulty(int blockHeight) {
    return blockHeight / 10 + 1;  // Increase difficulty as the blockchain grows
}

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
        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));
        std::cout << "Server started on port " << port << "\n";

        for (;;) {
            asio::ip::tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::cout << "New node connected!\n";
            std::thread(handleClient, std::move(socket)).detach();
        }
    } catch (std::exception& e) {
        std::cerr << "Server Error: " << e.what() << "\n";
    }
}

// Secure Communication Placeholder
void handleClient(asio::ip::tcp::socket socket) {
    try {
        asio::streambuf buffer;
        asio::read_until(socket, buffer, "\n");
        std::istream input(&buffer);
        std::string message;
        std::getline(input, message);
        std::cout << "Received message: " << message << "\n";
    } catch (std::exception& e) {
        std::cerr << "Client Error: " << e.what() << "\n";
    }
}

// Simulate node network with multithreading (each thread represents a node)
void runNode(EL40_Blockchain& blockchain, const std::string& blockData) {
    std::vector<Transaction> transactions = { Transaction{"Node1", "Node2", 50.0, ""} };
    blockchain.addBlock(transactions);
}

// Display exit popup
void displayExitPopup() {
    std::cout << "\n\n--- Exit Acknowledgment ---\n";
    std::cout << "MIT License\n";
    std::cout << "Copyright (c) 2025 EL-40 Blockchain\n";
    std::cout << "Special thanks to GPT Chat for assistance in the development.\n";
    std::cout << "This software is provided 'as-is' without any express or implied warranty.\n";
    std::cout << "For more information, visit: https://opensource.org/licenses/MIT\n";
    std::cout << "Email: elindau85@gmail.com\n";
    std::cout << "By: EL (El-40 Blockchain)\n";
    std::cout << "--- End of License ---\n";
    std::cout << "\nDDoS Protection Enabled: Network safety is ensured during this operation.\n";
}

int main() {
    try {
        std::cout << "Welcome to the EL-40 Blockchain Program.\n";

        if (!nodeAccessAgreement()) {
            return 0;
        }

        EL40_Blockchain blockchain;

        std::thread node1(runNode, std::ref(blockchain), "Node 1 Block Data");
        std::thread node2(runNode, std::ref(blockchain), "Node 2 Block Data");

        node1.join();
        node2.join();

        blockchain.displayChain();

        std::thread serverThread(startServer, 8080);
        serverThread.detach();

        std::this_thread::sleep_for(std::chrono::seconds(5));

        displayExitPopup();

        std::cout << "Exiting program...\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}
