#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>

#define WORDLIST_FILE "data/rockyou-1m.txt"
#define HASHED_PASSWORDS_FILE "data/hashed_pass.txt"

// Custom hash function
char* custom_hash(const char* input) {
    unsigned int hash = 0;
    const int prime_multiplier = 31;

    for (int i = 0; i < strlen(input); i++) {
        hash = (hash * prime_multiplier) + input[i];
    }

    // Convert hash to a hex string
    char* hashed_str = malloc(9);  // 8 hex digits plus null terminator
    sprintf(hashed_str, "%08x", hash);

    return hashed_str;
}

// Read the wordlist into an array
char** read_wordlist(const char* wordlist_file, int* count) {
    FILE* wordlist = fopen(wordlist_file, "r");
    if (!wordlist) {
        fprintf(stderr, "Failed to open wordlist file: %s\n", wordlist_file);
        return NULL;
    }

    char** passwords = NULL;
    char buffer[256];
    *count = 0;

    while (fgets(buffer, sizeof(buffer), wordlist)) {
        passwords = realloc(passwords, sizeof(char*) * (*count + 1));
        passwords[*count] = strdup(buffer);
        (*count)++;
    }

    fclose(wordlist);
    return passwords;
}

void hash_wordlist(const char* wordlist_file, const char* hashed_passwords_file) {
    int count = 0;
    char** passwords = read_wordlist(wordlist_file, &count);
    if (!passwords) {
        return;
    }

    // Parallel hashing
    char** hashed_passwords = malloc(sizeof(char*) * count);

    double start_hash = omp_get_wtime();

    #pragma omp parallel for num_threads(3) shared(passwords, hashed_passwords) schedule(static)
    for (int i = 0; i < count; i++) {
        // Remove newline characters from each password
        passwords[i][strcspn(passwords[i], "\r\n")] = '\0';
        hashed_passwords[i] = custom_hash(passwords[i]);
    }

    double end_hash = omp_get_wtime();
    double hashing_time = (end_hash - start_hash) * 1000;
    printf("Time taken to hash the wordlist: %f milliseconds\n", hashing_time);

    // Write the hashed passwords to file sequentially
    FILE* output = fopen(hashed_passwords_file, "w");
    if (!output) {
        fprintf(stderr, "Failed to open hashed passwords file: %s\n", hashed_passwords_file);
        return;
    }

    for (int i = 0; i < count; i++) {
        fprintf(output, "%s\n", hashed_passwords[i]);
        free(hashed_passwords[i]);
    }

    fclose(output);
    free(hashed_passwords);
    free(passwords);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }

    hash_wordlist(WORDLIST_FILE, HASHED_PASSWORDS_FILE);

    const char* password_to_crack = argv[1];
    char* hashed_password = custom_hash(password_to_crack);

    FILE* hashed_passwords = fopen(HASHED_PASSWORDS_FILE, "r");
    if (!hashed_passwords) {
        fprintf(stderr, "Failed to open hashed passwords file: %s\n", HASHED_PASSWORDS_FILE);
        free(hashed_password);
        return 1;
    }

    fseek(hashed_passwords, 0, SEEK_END);
    long file_size = ftell(hashed_passwords);
    rewind(hashed_passwords);

    char* hashed_data = malloc(file_size + 1);
    fread(hashed_data, 1, file_size, hashed_passwords);
    hashed_data[file_size] = '\0';

    char** lines = NULL;
    int line_count = 0;

    // Split the data into lines
    char* token = strtok(hashed_data, "\n");
    while (token != NULL) {
        lines = realloc(lines, sizeof(char*) * (line_count + 1));
        lines[line_count] = strdup(token);
        token = strtok(NULL, "\n");
        line_count++;
    }

    int found = 0;
    int found_index = -1;

    double start_time = omp_get_wtime();

    #pragma omp parallel for num_threads(4) schedule(static)
    for (int i = 0; i < line_count; i++) {
        if (found) continue; // Skip the rest of the loop if the password is found
        if (strcmp(lines[i], hashed_password) == 0) {
            #pragma omp critical
            {
                if (!found) {
                    found = 1;
                    found_index = i;
                }
            }
        }
    }

    double end_time = omp_get_wtime();
    double search_time = (end_time - start_time) * 1000;

    fclose(hashed_passwords);
    free(hashed_password);

    for (int i = 0; i < line_count; i++) {
        free(lines[i]);
    }
    free(lines);
    free(hashed_data);

    if (found) {
        printf("The cracked password is %s\n", password_to_crack);
    } else {
        printf("Password not found!\n");
    }

    printf("Time of execution (searching): %.5f milliseconds\n", search_time);

    return 0;
}
