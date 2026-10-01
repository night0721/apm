#include <dirent.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "arg.h"

#include "aes256.h"
#include "blake2b.h"

#define KEY_SIZE 32
#define IV_SIZE 16
#define SALT_SIZE 16

char *argv0;

void die(char *str);
char *get_master_key(void);
void random_bytes(uint8_t *bytes, size_t size);

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
	printf("Usage: %s [-vhL] [[-e | -R | -I | -Q] <password>] [-M <file>] [-G "
		   "<password> <length>]\n",
		   argv0);
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

	char **files = NULL;
	size_t file_count = 0;
	size_t file_capacity = 0;

	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
			if (file_count == file_capacity) {
				file_capacity = file_capacity ? file_capacity * 2 : 32;
				files = realloc(files, file_capacity * sizeof(*files));
				if (!files)
					die("realloc");
			}

			files[file_count] = strdup(dp->d_name);
			if (!files[file_count])
				die("strdup");

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

		if (snprintf(path, sizeof(path), "%s/%s", basepath, files[i]) >=
			sizeof(path)) {
			free(files[i]);
			continue;
		}

		struct stat st;
		if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
			tree(path, depth + 1);

		free(files[i]);
	}

	free(files);
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
	char *dir = memalloc(len);

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
	char *path = memalloc(len);
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

void encrypt_password(const char *name, char *password, size_t password_len)
{
	char *m_key = get_master_key();
	uint8_t key[KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t salt[SALT_SIZE];

	/* generate random bytes for iv */
	random_bytes(iv, sizeof(iv));
	random_bytes(salt, sizeof(salt));

	/* Derive the AES key from the master key and per-entry salt. */
	size_t kdf_len = strlen(m_key) + sizeof(salt);
	uint8_t *kdf_input = memalloc(kdf_len);
	memcpy(kdf_input, m_key, strlen(m_key));
	memcpy(kdf_input + strlen(m_key), salt, sizeof(salt));
	blake2b(key, KEY_SIZE, NULL, 0, kdf_input, kdf_len);
	free(kdf_input);

	size_t data_len = EncryptData((uint8_t *) password, password_len, key, iv);

	char *filepath = get_passfile(name);
	FILE *file = fopen(filepath, "wb");
	if (file == NULL) {
		free(m_key);
		free(filepath);
		die("Error opening pass file to write");
	}

	fwrite(iv, sizeof(iv), 1, file);
	fwrite(salt, sizeof(salt), 1, file);
	fwrite(password, data_len, 1, file);

	fclose(file);
	free(filepath);
	free(m_key);
}

void decrypt_password(const char *name, int open)
{
	char *m_key = get_master_key();
	uint8_t key[KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t salt[SALT_SIZE];

	char *filepath = get_passfile(name);
	FILE *file = fopen(filepath, "rb");
	if (file == NULL) {
		free(m_key);
		free(filepath);
		die("Error opening pass file to read");
	}

	/* get iv from file */
	if (fread(iv, 1, sizeof(iv), file) != sizeof(iv))
		die("Invalid pass file");

	if (fread(salt, 1, sizeof(salt), file) != sizeof(salt))
		die("Invalid pass file");

	fseek(file, 0, SEEK_END);
	if (ftell(file) <= sizeof(iv) + sizeof(salt)) {
		free(m_key);
		free(filepath);
		fclose(file);
		die("Empty file");
	}
	size_t ciphered_len = ftell(file) - sizeof(iv) - sizeof(salt);
	fseek(file, sizeof(iv) + sizeof(salt), SEEK_SET);

	char ciphered[ciphered_len];
	fread(ciphered, 1, ciphered_len, file);

	size_t kdf_len = strlen(m_key) + sizeof(salt);
	uint8_t *kdf_input = memalloc(kdf_len);
	memcpy(kdf_input, m_key, strlen(m_key));
	memcpy(kdf_input + strlen(m_key), salt, sizeof(salt));
	blake2b(key, KEY_SIZE, NULL, 0, kdf_input, kdf_len);
	free(kdf_input);

	size_t data_len = DecryptData((uint8_t *)ciphered, ciphered_len, key, iv);
	ciphered[data_len] = '\0';

	if (open) {
		char *editor = getenv("EDITOR");
		if (editor == NULL) {
			die("EDITOR not defined");
		}

		const char *runtime = getenv("XDG_RUNTIME_DIR");

		if (runtime == NULL)
			die("XDG_RUNTIME_DIR not defined");

		char tmp_f[PATH_MAX];
		FILE *tmp;

		if (snprintf(tmp_f, sizeof(tmp_f),
		             "%s/apm-XXXXXX", runtime) >= sizeof(tmp_f))
			die("Temporary path too long");

		int tmp_fd = mkstemp(tmp_f);
		if (tmp_fd < 0)
			die("Cannot create temporary file");

		if (fchmod(tmp_fd, 0600) != 0) {
			close(tmp_fd);
			unlink(tmp_f);
			die("Cannot set temporary file permissions");
		}

		tmp = fdopen(tmp_fd, "w+");
		if (tmp == NULL) {
			close(tmp_fd);
			unlink(tmp_f);
			die("Cannot open temporary file");
		}

		fprintf(tmp, "%s\n", ciphered);
		fclose(tmp);
		char *cmd = memalloc(strlen(editor) + strlen(tmp_f) + 1);
		sprintf(cmd, "%s %s", editor, tmp_f);
		system(cmd);
		free(cmd);

		tmp = fopen(tmp_f, "r");
		if (tmp == NULL) {
			unlink(tmp_f);
			die("Cannot reopen temporary file");
		}

		fseek(tmp, 0, SEEK_END);
		long tmp_size = ftell(tmp);
		fseek(tmp, 0, SEEK_SET);
		char *content = memalloc(tmp_size + 1);
		fread(content, 1, tmp_size, tmp);
		content[tmp_size] = '\0';
		encrypt_password(name, content, tmp_size);
		free(content);
		fclose(tmp);
		unlink(tmp_f);
	} else {
		printf("%s\n", ciphered);
	}

	free(m_key);
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
		if ((fstat(fileno(key_file), &st) == 0) && (S_ISREG(st.st_mode))) {
			size_t pass_size = st.st_size;
			m_key = memalloc(pass_size);
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

void random_bytes(uint8_t *bytes, size_t size)
{
	FILE *file = fopen("/dev/urandom", "r");
	if (file == NULL) {
		die("Cannot open /dev/urandom");
	}
	fread(bytes, 1, size, file);
	fclose(file);
}

void generate_password(char *name, int length)
{
	srand(time(NULL));
	const char *characters =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY"
		"Z01234567890123456789~`!@#$%^&*()-_+=[]{}|/,.<>;:'";
	size_t characters_len = strlen(characters);
	char *random_string = memalloc(length + 1);
	for (int i = 0; i < length; i++) {
		random_string[i] = characters[rand() % (characters_len - 1)];
	}
	random_string[length] = '\0';
	printf("The generated password for %s is: %s\n", name, random_string);
	encrypt_password(name, random_string, strlen(random_string));
	free(random_string);
}

void die(char *str)
{
	fprintf(stderr, "apm: %s\n", str);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	/* disable core dump for security */
	setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0});

	ARGBEGIN
	{
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
		encrypt_password(EARGF(usage()), pw, strlen(pw));
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
		char *content = memalloc(file_size + 1);
		fread(content, sizeof(char), file_size, file);
		content[file_size] = '\0';
		char *f_basename = basename(filename);
		char *dot = strrchr(f_basename, '.');
		if (dot != NULL) {
			*dot = '\0';
		}
		encrypt_password(f_basename, content, file_size);
		exit(EXIT_SUCCESS);
		break;
	case 'G':;
		if (argc > 0)
			--argc, ++argv;
		goto run;
	default:
		usage();
	}
	ARGEND;

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
