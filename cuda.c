// %%cuda
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cuda_runtime.h>

#define PASSWORD_TO_CRACK "vjht08"
#define WORDLIST_FILE "data/rockyou-1m.txt"
#define HASHED_PASSWORDS_FILE "data/hashed_pass.txt"

// Task parallelism
__global__ void cuda_custom_hash(const char* dev_inputs, unsigned int* dev_hashes, int num_strings, int max_len) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x; // Calculate thread id
    const int prime_multiplier = 31;

    if (tid < num_strings) {
        unsigned int local_hash = 0;
        const char* input = dev_inputs + tid * max_len; // Get the input string for this thread

        for (int i = 0; i < max_len && input[i] != '\0'; i++) {
            local_hash = (local_hash * prime_multiplier) + input[i];
        }

        dev_hashes[tid] = local_hash; // Store the hash in the output array indexed by thread id
    }
}

// Data parallelism
__global__ void cuda_search_hash(unsigned int* dev_hashes, unsigned int target_hash, int num_strings, int* dev_found) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x; // Calculate thread id

    if (tid < num_strings && dev_hashes[tid] == target_hash) { // Check if the hash matches the target hash
        atomicAdd(dev_found, 1); // Mark that we found the target hash atomically to prevent race conditions
    }
}

int main() {
    FILE* wordlist_filehandler = fopen(WORDLIST_FILE, "r");
    if (wordlist_filehandler == NULL) {
        printf("Failed to open wordlist file.\n");
        return 0;
    }

    const int max_password_length = 256;
    const int max_passwords = 1000000;

    char* passwords = (char*)malloc(max_passwords * max_password_length);
    int password_count = 0;

    while (password_count < max_passwords && fscanf(wordlist_filehandler, "%s", passwords + password_count * max_password_length) == 1) {
        password_count++;
    }

    fclose(wordlist_filehandler);

    char* dev_passwords;
    unsigned int* dev_hashes;
    cudaMalloc(&dev_passwords, max_passwords * max_password_length); // Allocate memory on gpu for passwords based on password count and max password length
    cudaMalloc(&dev_hashes, max_passwords * sizeof(unsigned int)); // Allocate memory on gpu for hashes based on password count

    cudaMemcpy(dev_passwords, passwords, max_passwords * max_password_length, cudaMemcpyHostToDevice); // Copy passwords to gpu

    clock_t start_hash = clock(); // Start timing for hashing

    int block_size = 50; // Number of threads per block
    int grid_size = (password_count + block_size - 1) / block_size; // calculate grid size based on password count
    cuda_custom_hash<<<grid_size, block_size>>>(dev_passwords, dev_hashes, password_count, max_password_length); // Launch kernel for hashing

    unsigned int* host_hashes = (unsigned int*)malloc(password_count * sizeof(unsigned int));
    cudaMemcpy(host_hashes, dev_hashes, password_count * sizeof(unsigned int), cudaMemcpyDeviceToHost); // Copy hashes back to host (CPU)

    FILE* hashed_passwords_filehandler = fopen(HASHED_PASSWORDS_FILE, "w");
    for (int i = 0; i < password_count; i++) {
        fprintf(hashed_passwords_filehandler, "%08x\n", host_hashes[i]); // Write hashed password to file separated by newline
    }

    fclose(hashed_passwords_filehandler);

    clock_t end_hash = clock(); // End timing for hashing
    double hashing_time_ms = ((double)(end_hash - start_hash) / CLOCKS_PER_SEC) * 1000;

    printf("Time to hash passwords: %.5f ms\n", hashing_time_ms);

    clock_t start_search = clock(); // Start timing for searching

    // Prepare for parallelized search
    unsigned int target_hash = 0;
    const char* password_to_crack = PASSWORD_TO_CRACK;
    for (int i = 0; password_to_crack[i] != '\0'; i++) {
        target_hash = (target_hash * 31) + password_to_crack[i]; // Hash the password to crack
    }

    int* dev_found; // Flag to indicate if password is found
    cudaMalloc(&dev_found, sizeof(int)); // Allocate memory on gpu for found flag
    int init_val = 0;
    cudaMemcpy(dev_found, &init_val, sizeof(int), cudaMemcpyHostToDevice); // Initialize found flag

    // Launch kernel for parallelized search
    grid_size = (password_count + block_size - 1) / block_size; // calculate grid size based on password count
    cuda_search_hash<<<grid_size, block_size>>>(dev_hashes, target_hash, password_count, dev_found); // Launch kernel for searching

    int found;
    cudaMemcpy(&found, dev_found, sizeof(int), cudaMemcpyDeviceToHost); // Copy found flag back to host (CPU)

    if (found > 0) {
        printf("Cracked password is: %s\n", PASSWORD_TO_CRACK);
    } else {
        printf("Password not found!\n");
    }

    clock_t end_search = clock(); // End timing for searching
    double search_time_ms = ((double)(end_search - start_search) / CLOCKS_PER_SEC) * 1000;

    printf("Time to search for password: %.5f ms\n", search_time_ms);

    free(passwords);
    free(host_hashes);
    cudaFree(dev_passwords);
    cudaFree(dev_hashes);
    cudaFree(dev_found);

    return 0;
}
