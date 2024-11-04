#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <linux/limits.h>

#include <sodium.h>

#include "arg.h"

#define KEY_SIZE crypto_secretbox_KEYBYTES
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define SALT_SIZE crypto_pwhash_SALTBYTES

char *argv0;

void die(char *str);
char *get_master_key(void);

void *memalloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr) {
        perror("apm");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void usage(void)
{
    printf("Usage: %s [-vhL] [[-e | -R | -I | -Q] <password>] [-M <file>] [-G <password> <length>]\n", argv0);
    exit(EXIT_SUCCESS);
}

int compare(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

void tree(const char *basepath, int depth)
{
    char path[PATH_MAX];
    struct dirent *dp;
    DIR *dir = opendir(basepath);

    if (!dir)
        return;

    /* max 1024 files */
    char *files[1024];
    int file_count = 0;

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            files[file_count] = strdup(dp->d_name);
            file_count++;
        }
    }

    qsort(files, file_count, sizeof(char *), compare);

    for (int i = 0; i < file_count; i++) {
        for (int j = 0; j < depth - 1; j++) {
            printf("│   ");
        }

        if (depth > 0) {
            printf("├── ");
        }

        printf("%s\n", files[i]);

        strcpy(path, basepath);
        strcat(path, "/");
        strcat(path, files[i]);

        tree(path, depth + 1);

        free(files[i]);
    }

    closedir(dir);
}

char *get_apm(void)
{
    char dirname[] = "apm";
    const char *apm_dir = getenv("APM_DIR");
    /* for / and null */
    size_t len = 2;
    if (apm_dir == NULL) {
        apm_dir = getenv("XDG_DATA_HOME");
        if (apm_dir == NULL) {
            apm_dir = getenv("HOME");
            if (apm_dir == NULL) {
                die("HOME not defined");
            }
        }
        len += strlen(dirname);
    } else {
        /* no / */
        len -= 1;
    }
    size_t dir_len = strlen(apm_dir);
    len += dir_len;
    char *dir = memalloc(len * sizeof(char));

    /* check if it is apm_DIR or other */
    if (len > dir_len) {
        snprintf(dir, len, "%s/%s", apm_dir, dirname);
    } else {
        strncpy(dir, apm_dir, len);
    }
    struct stat stats;
    /* check defined path is directory */
    if (!((stat(dir, &stats) == 0) && S_ISDIR(stats.st_mode))) {
        if (mkdir(dir, S_IRWXU)) { /* 700 */
            die("Cannot initialize directory");
        }
    }
    return dir;
}

char *get_passfile(const char *key)
{
    char *dir = get_apm();
    /* concat file name */
    /* / and null */
    size_t len = strlen(dir) + strlen(key) + 2; 
    char *path = memalloc(len * sizeof(char));
    snprintf(path, len, "%s/%s", dir, key);
    free(dir);
    return path;
}

char *get_password(void)
{
    size_t len;
    char *password = NULL;
    printf("Enter password to encrypt: \n");
    getline(&password, &len, stdin);
    /* remove newline character */
    password[strcspn(password, "\n")] = '\0';
    return password;
}

void encrypt_password(const char *name, char *password)
{
    char *m_key = get_master_key();
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char nonce[NONCE_SIZE];

    /* generate random bytes for salt and nonce(number used once) */
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));
    /* hash master password to give us the key for encrypting the password */
    if (crypto_pwhash(key, sizeof(key), m_key, strlen(m_key), salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_free(m_key);
        perror("apm");
        die("Cannot create key");
    }
    size_t pw_len = strlen(password);
    /* Include space for authentication tag */
    size_t ciphered_len = crypto_secretbox_MACBYTES + pw_len;
    char ciphered[ciphered_len];

    /* encrypt password */
    if (crypto_secretbox_easy((unsigned char *) ciphered, 
                (unsigned char *) password, pw_len,
                nonce, key) != 0) {
        sodium_free(m_key);
        die("Error encrypting password");
    }

    char *filepath = get_passfile(name);
    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        sodium_free(m_key);
        free(filepath);
        die("Error opening pass file to write");
    }
   
    fwrite(salt, sizeof(salt), 1, file);
    fwrite(nonce, sizeof(nonce), 1, file);
    fwrite(ciphered, ciphered_len, 1, file);

    fclose(file);
    free(filepath);
    sodium_free(m_key);
}

void decrypt_password(const char *name, int open)
{
    char *m_key = get_master_key();
    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char key[KEY_SIZE];

    char *filepath = get_passfile(name);
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        sodium_free(m_key);
        free(filepath);
        die("Error opening pass file to read");
    }
    
    /* get salt and nonce from file */
    fread(salt, sizeof(char), sizeof(salt), file);
    fread(nonce, sizeof(char), sizeof(nonce), file);

    fseek(file, 0, SEEK_END);
    size_t ciphered_len = ftell(file) - sizeof(salt) - sizeof(nonce);
    fseek(file, sizeof(salt) + sizeof(nonce), SEEK_SET);

    char ciphered[ciphered_len];
    fread(ciphered, sizeof(char), ciphered_len, file);
    if (crypto_pwhash(key, sizeof(key), m_key, strlen(m_key), salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_free(m_key);
        free(filepath);
        perror("apm");
        die("Cannot create key");
    }
    /* take authentication bytes away */
    size_t deciphered_len = ciphered_len - crypto_secretbox_MACBYTES;
    char deciphered[deciphered_len];
    if (crypto_secretbox_open_easy((unsigned char *) deciphered, 
                (unsigned char *) ciphered, ciphered_len, nonce, key) != 0) {
        sodium_free(m_key);
        free(filepath);
        fclose(file);
        die("Error decrypting password");
    }

    deciphered[deciphered_len] = '\0';
    if (open) {
        char *editor = getenv("EDITOR");
        if (editor == NULL) {
            die("EDITOR not defined");
        }
        char tmp_f[] = "/tmp/apm";
        FILE *tmp = fopen(tmp_f, "w+");
        fprintf(tmp, "%s\n", deciphered);
        fclose(tmp);
        char *cmd = memalloc((strlen(editor) + strlen(tmp_f) + 1) * sizeof(char));
        sprintf(cmd, "%s %s", editor, tmp_f);
        system(cmd);
        free(cmd);
        tmp = fopen(tmp_f, "r");
        fseek(tmp, 0, SEEK_END);
        long tmp_size = ftell(tmp);
        fseek(tmp, 0, SEEK_SET);
        char content[tmp_size + 1];
        fgets(content, tmp_size, tmp);
        encrypt_password(name, content);
        fclose(tmp);
    } else {
        printf("%s\n", deciphered);
    }

    sodium_free(m_key);
    fclose(file);
}

char *get_master_key(void)
{
    char *key_path = getenv("APM_KEY");
    char *m_key = NULL;
    if (key_path != NULL) {
        FILE *key_file = fopen(key_path, "r");
        if (key_file == NULL) {
            perror("apm");
            exit(EXIT_FAILURE);
        }
        struct stat st;
        if ((fstat(fileno(key_file), &st) == 0) || (S_ISREG(st.st_mode))) {
            size_t pass_size = st.st_size;
            m_key = (char *) sodium_malloc(pass_size * sizeof(char));
            if (m_key == NULL) {
                perror("apm");
                exit(EXIT_FAILURE);
            }
            if (fgets(m_key, pass_size, key_file) == NULL) {
                perror("apm");
                exit(EXIT_FAILURE);
            }
        }
    } else {
        fprintf(stderr, "apm: You are required to set APM_KEY to pass file\n");
        exit(EXIT_FAILURE);
    }
    return m_key;
}

void generate_password(char*name, int length)
{
    srand(time(NULL));
    const char *characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789~`!@#$%^&*()-_+=[]{}|/,.<>;:'";
    size_t characters_len = strlen(characters);
    char *random_string = memalloc(length + 1);
    for (int i = 0; i < length; i++) {
        random_string[i] = characters[rand() % (characters_len - 1)];
    }
    random_string[length] = '\0';
    printf("The generated password for %s is: %s\n", name, random_string);
    encrypt_password(name, random_string);
    free(random_string);
}

void die(char *str)
{
    fprintf(stderr, "apm: %s\n", str);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    if (sodium_init() == -1) {
        die("Error initializing sodium");
    }

    /* disable core dump for security */
    setrlimit(RLIMIT_CORE, &(struct rlimit) {0, 0});
    
    ARGBEGIN {
        case 'h':
            usage();
            break;
        case 'v':
            printf("apm 1.0.0\n");
            exit(EXIT_SUCCESS);
            break;
        case 'e':
            decrypt_password(EARGF(usage()), 1);
            exit(EXIT_SUCCESS);
            break;
        case 'R':;
            char *pass_file = get_passfile(EARGF(usage()));
            if (remove(pass_file)) {
                perror("apm");
            } else {
                printf("Removed %s\n", basename(pass_file));
            }
            free(pass_file);
            exit(EXIT_SUCCESS);
            break;
        case 'I':;
            char *pw = get_password();
            encrypt_password(EARGF(usage()), pw);
            free(pw);
            exit(EXIT_SUCCESS);
            break;
        case 'Q':
            decrypt_password(EARGF(usage()), 0);
            exit(EXIT_SUCCESS);
            break;
        case 'L':;
            char *apm = get_apm();
            tree(apm, 0);
            free(apm);
            exit(EXIT_SUCCESS);
            break;
        case 'M':;
            char *filename = EARGF(usage());
            FILE *file = fopen(filename, "r");
            if (file == NULL) {
                die("Cannot open file to read");
            }
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fseek(file, 0, SEEK_SET);
            char *content = memalloc(file_size * sizeof(char));
            fread(content, sizeof(char), file_size, file);
            char *f_basename = basename(filename);
            char *dot = strrchr(f_basename, '.');
            if (dot != NULL) {
                *dot = '\0';
            }
            encrypt_password(f_basename, content);
            exit(EXIT_SUCCESS);
            break;
        case 'G':;
            if (argc > 0)
                --argc, ++argv;
            goto run;
        default:
            usage();
    } ARGEND;

    run:
        switch (argc) {
            case 0:
                usage();
                break;
            case 1:
                decrypt_password(argv[0], 0);
                break;
            case 2:
                generate_password(argv[0], atoi(argv[1]));
                break;
        }

    return 0;

}
