#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define PLAIN_PASSWORDS_FILE "data/rockyou-1m.txt"
#define HASHED_PASSWORDS_FILE "data/hashed_pass.txt"

// Custom hash function
char* custom_hash(const char* input) {
    unsigned int hash = 0;
    const int prime_multiplier = 31;

    for (int i = 0; i < strlen(input); i++) {
        hash = (hash * prime_multiplier) + input[i];
    }

    // Convert hash to a hex string
    char* hashed_str = (char*)malloc(9); // 8 hex digits + null terminator
    sprintf(hashed_str, "%08x", hash);
    return hashed_str;
}

// Function to hash passwords and write them to the hashed password file
void hash_and_save_passwords(MPI_File* input, int rank, int size, int overlap) {
    MPI_Offset global_start, global_end;
    MPI_Offset file_size;
    int mysize;

    MPI_File_get_size(*input, &file_size);
    file_size--;  // Remove EOF

    mysize = file_size / size;

    global_start = rank * mysize;
    global_end = global_start + mysize - 1;

    if (rank == size - 1) {
        global_end = file_size - 1;
    }

    if (rank != size - 1) {
        global_end += overlap;
    }

    mysize = global_end - global_start + 1;

    char* chunk = (char*)malloc((mysize + 1) * sizeof(char));  // +1 for null terminator
    memset(chunk, 0, mysize + 1);  // Initialize buffer

    MPI_File_read_at_all(*input, global_start, chunk, mysize, MPI_CHAR, MPI_STATUS_IGNORE);

    int loc_start = 0;
    int loc_end = mysize - 1;

    // Find correct boundaries to avoid data overlaps or truncation
    if (rank != 0) {
        while (chunk[loc_start] != '\n' && loc_start < loc_end) loc_start++;
        loc_start++;  // Move to start of next line
    }

    if (rank != size - 1) {
        loc_end -= overlap;
        while (chunk[loc_end] != '\n' && loc_end > loc_start) loc_end++;
    }

    MPI_Offset chunk_size = loc_end - loc_start + 1;

    // Collect hashed results for each process
    char* hashed_results = (char*)malloc((chunk_size + 1) * sizeof(char));  // +1 for null terminator
    memset(hashed_results, 0, chunk_size + 1);

    int offset = 0;
    for (int i = loc_start; i <= loc_end; i++) {
        int line_start = i;
        while (chunk[i] != '\n' && i <= loc_end) {
            i++;
        }

        int line_length = i - line_start;
        if (line_length > 0) {
            char* plain_password = (char*)malloc((line_length + 1) * sizeof(char));  // +1 for null terminator
            strncpy(plain_password, &chunk[line_start], line_length);
            plain_password[line_length] = '\0';

            char* hashed_password = custom_hash(plain_password);

            strncpy(&hashed_results[offset], hashed_password, 8);  // 8 hex digits for hash
            offset += 8;

            hashed_results[offset] = '\n';  // Add newline after each hashed password
            offset += 1;  // Move to next position

            free(plain_password);
            free(hashed_password);
        }
    }

    free(chunk);

    // Gather results at the master process (rank 0)
    int total_size = chunk_size + 1;  // Account for newline
    char* gathered_results = NULL;
    if (rank == 0) {
        gathered_results = (char*)malloc((total_size * size) * sizeof(char));
        memset(gathered_results, 0, total_size * size);
    }

    MPI_File_close(input);

    // printf("Rank %d: %s\n", rank, hashed_results);

    MPI_Gather(hashed_results, total_size, MPI_CHAR, gathered_results, total_size, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Master process writes the gathered results to the output file
    if (rank == 0) {
        gathered_results[total_size * size - 1] = '\n'; // Add newline at the end
        // save to file
        MPI_File hashed_output;
        MPI_File_open(MPI_COMM_SELF, HASHED_PASSWORDS_FILE, MPI_MODE_CREATE | MPI_MODE_WRONLY, MPI_INFO_NULL, &hashed_output);

        MPI_File_write(hashed_output, gathered_results, total_size * size, MPI_CHAR, MPI_STATUS_IGNORE);

        MPI_File_close(&hashed_output);
        free(gathered_results);
    }

    free(hashed_results);
}

// Function to search hashed passwords in the wordlist
int search_hashed_password(MPI_File* input, const char* hashed_password, int rank, int size, int overlap) {
    MPI_Offset global_start;
    MPI_Offset global_end;
    int mysize;

    MPI_Offset file_size;
    MPI_File_get_size(*input, &file_size);

    file_size--;  // Removing EOF
    mysize = file_size / size;
    global_start = rank * mysize;
    global_end = global_start + mysize - 1;

    if (rank == size - 1) {
        global_end = file_size - 1;
    }

    if (rank != size - 1) {
        global_end += overlap;
    }

    mysize = global_end - global_start + 1;

    char* buff = (char*)malloc((mysize + 1) * sizeof(char));
    MPI_File_read_at_all(*input, global_start, buff, mysize, MPI_CHAR, MPI_STATUS_IGNORE);

    buff[mysize] = '\0';

    int loc_start = 0;
    int loc_end = mysize - 1;

    if (rank != 0) {
        while (buff[loc_start] != '\n') loc_start++;
        loc_start++;
    }

    if (rank != size - 1) {
        loc_end -= overlap;
        while (buff[loc_end] != '\n') loc_end++;
    }

    int j = 0;
    for (int i = loc_start; i <= loc_end; i++) {
        if (buff[i] == '\n') {
            j = 0;
            continue;
        }

        if (buff[i] == hashed_password[j]) {
            j++;
        }

        if (j == strlen(hashed_password)) {
            return 1;
        }
    }

    free(buff);
    return 0;
}

// Main Function
int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }

    const char* password_to_crack = argv[1];
    char* hashed_password = custom_hash(password_to_crack);

    MPI_File plain_input;
    MPI_File hashed_input;

    int rank, size;
    int error_code;
    const int overlap = 100;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // Hashing phase
    error_code = MPI_File_open(MPI_COMM_WORLD, PLAIN_PASSWORDS_FILE, MPI_MODE_RDONLY, MPI_INFO_NULL, &plain_input);
    if (error_code) {
        if (rank == 0) {
            fprintf(stderr, "Can't open the plain passwords file.\n");
        }
        MPI_Finalize();
        return 2;
    }

    // Hash passwords and save to file
    hash_and_save_passwords(&plain_input, rank, size, overlap);

    // Cracking phase
    error_code = MPI_File_open(MPI_COMM_WORLD, HASHED_PASSWORDS_FILE, MPI_MODE_RDONLY, MPI_INFO_NULL, &hashed_input);
    if (error_code) {
        if (rank == 0) {
            fprintf(stderr, "Can't open the hashed passwords file for reading.\n");
        }
        MPI_Finalize();
        return 4;
    }

    double start_time = MPI_Wtime();

    int success = search_hashed_password(&hashed_input, hashed_password, rank, size, overlap);

    double end_time = MPI_Wtime();

    if (success) {
        printf("Password found!\nSearch Time taken: %.3f ms\n", (end_time - start_time) * 1000);
    }

    MPI_File_close(&hashed_input);
    MPI_Finalize();

    free(hashed_password);

    return 0;
}
