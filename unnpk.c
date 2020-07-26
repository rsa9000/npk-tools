/**
 * Mikrotik's NPK package processor/unpacker
 *
 * Copyright (c) 2012-2018, Sergey Ryazanov <ryazanov.s.a@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <zlib.h>

#include "npk.h"

#define VERSION_STR	"1.1.1"

#define FL_DUMP		0x01	/* Dump internal NPK structures flag */
#define FL_LIST		0x02	/* List NPK files */

/* Operation options */
struct options {
	const char *file_in;	/* Input file for processing */
	off_t file_in_size;	/* Input file size */
	const char *dir_out;	/* Output directory for extracting */
	enum {
		OP_UNKNOWN = 0,
		OP_HELP,
		OP_LIST,
		OP_EXTRACT,
	} op;			/* Selected operation */
	unsigned verb;		/* Verbose level */
	unsigned flags;		/* Fags field see OPS_XXX defs */
};

/* Type (or id) to name mapping item descriptor */
struct map_entry {
	unsigned id;
	char *name;
};

/* List of NPK partition types names */
static const struct map_entry part_types_names[] = {
	{ 0, "Unknown"},
	{ NPK_PART_PKG_INFO, "Package information"},
	{ NPK_PART_PKG_DESC, "Package description"},
	{ NPK_PART_FILES, "Files container"},
	{ NPK_PART_INSTALL, "Install script"},
	{ NPK_PART_UNINSTALL, "Uninstall script"},
	{ NPK_PART_PKG_ARCH, "Package architecture"},
	{ NPK_PART_PKG_MAIN, "Main package information"},
	{ NPK_PART_SQUASHFS, "Squash filesystem image"},
	{ NPK_PART_DIGEST, "Digest"},
	{ NPK_PART_RELTYPE, "Release type"},
	{ 0, NULL},
};

/* List of NPK files permissions names */
static const struct map_entry file_perms_names[] = {
	{ 0, "Unknown"},
	{ NPK_FILE_PERM_EXEC, "executable"},
	{ NPK_FILE_PERM_NOTEXEC, "not executable"},
	{ 0, NULL},
};

/* List of NPK partition types names */
static const struct map_entry file_types_names[] = {
	{ 0, "Unknown"},
	{ NPK_FILE_TYPE_DEV, "device"},
	{ NPK_FILE_TYPE_DIR, "directory"},
	{ NPK_FILE_TYPE_REGULAR, "regular"},
	{ 0, NULL},
};

static char *pkg_name;		/* The current processing package name */

/**
 * Performs type to name mapping and returns name string
 * arguments:
 *  * map - Input map
 *  * type - Type id which should be mapped
 *
 * First entry is used as default name if type not matched to any other entry.
 * Last map item should contain NULL as name to indicate end of list.
 */
static const char *type2name(const struct map_entry *map, const unsigned type)
{
	const struct map_entry *e = map;

	while (e->name != NULL) {
		if (e->id == type)
			return e->name;
		++e;
	}

	return map->name;
}

/**
 * Converts binary array to string and returns pointer to result string
 * arguments:
 *   * array - Input array
 *   * len - Input array byte length
 */
static char *array2str(const uint8_t *array, const unsigned len)
{
	static char buf[4 + /* N= */24 * 3 + 1] = {'h', 'e', 'x', ':'};	/* Output buffer for N hex items */
	char *p = buf + 4;
	unsigned i;

	for (i = 0; i < len; ++i) {
		p += sprintf(p, "%02X ", array[i]);
		if (((buf + sizeof(buf) - p) <= 4) && (len - i) > 2) {
			strcpy(p, "...");
			break;
		}
	}
	if (len == i)
		*(--p) = '\0';

	return buf;
}

/**
 * Recursively creates each element of specified path
 *
 * NB: This function modify passed string when recursivly call self.
 */
static void create_path(char *path)
{
	char *p;

	if (mkdir(path, 0777) == 0)
		return;
	if (EEXIST == errno)
		return;
	if (ENOENT == errno) {
		p = strrchr(path, '/');
		if (NULL == p) {	/* Impossible */
		} else {
			*p = '\0';
			create_path(path);
			*p = '/';
			mkdir(path, 0777);
		}
	} else {
		perror("mkdir");
	}
}

/**
 * Creates path for specified file
 *
 * This routine skip last right path component and try to create directory
 * from left path.
 */
static void create_file_path(char *path)
{
	char *p;

	p = strrchr(path, '/');
	if (NULL == p)	/* No directory prefix */
		return;
	if ('\0' == *(p + 1)) {	/* No file component */
		create_path(path);
	} else {
		*p = '\0';
		create_path(path);
		*p = '/';
	}
}

/**
 * Processes NPK file partition as package description, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_pkg_desc(uint8_t *data, const uint32_t size,
				   const struct options *opt)
{
	char buf[size + 1], *p, *e;
	size_t len = strnlen((char *)data, size);

	if ((opt->flags & FL_DUMP) == 0)
		return 0;

	strncpy(buf, (char *)data, len);
	buf[len] = '\0';

	p = buf;
	e = buf + len - 1;

	/* Remove leading newlines and spaces */
	while (*p == '\n' || *p == ' ')
		p++;
	/* Remove trailing newlines and spaces */
	while (*e == '\n' || *e == ' ')
		e--;

	printf("Description: %.*s\n", (int)(e - p + 1), p);

	return 0;
}

/**
 * Processes NPK file partition as files container, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_files(uint8_t *data, const uint32_t size, const struct options *opt)
{
	int ret;
	unsigned have;
	z_stream zstm;
	uint8_t out[16 * 1024], *p;
	char *tmp;
	FILE *file_out = NULL;
	struct npk_part_file_item_hdr hdr;
	enum {
		ST_INFLATE_HDR,		/* Decompress header */
		ST_INFLATE_NAME,	/* Decompress name */
		ST_INFLATE_DATA,	/* Decompress data */
		ST_DUMP_HDR,		/* Dump header */
		ST_DUMP_NAME,		/* Dump name */
		ST_DUMP_DATA,		/* Dump data */
		ST_DONE,		/* Break the circle */
	} state;

	zstm.zalloc = Z_NULL;
	zstm.zfree = Z_NULL;
	zstm.opaque = Z_NULL;
	zstm.avail_in = 0;
	zstm.next_in = Z_NULL;
	ret = inflateInit(&zstm);
	if (ret != Z_OK) {
		perror("inflateInit");
		return -EINVAL;
	}

	zstm.avail_in = size;
	zstm.next_in = data;
	state = ST_INFLATE_HDR;
	have = 0;

	while (state != ST_DONE) {
		switch (state) {
		case ST_INFLATE_HDR:
		case ST_INFLATE_NAME:
		case ST_INFLATE_DATA:
			if (0 == zstm.avail_in) {	/* No more input data */
				if (ST_INFLATE_HDR != state)
					fprintf(stderr, "Request additional input data but input buffer is empty.\n");
				state = ST_DONE;
				break;
			}
			if (have)
				memmove(out, p, have);
			p = out;
			zstm.avail_out = sizeof(out) - have;
			zstm.next_out = out + have;
			ret = inflate(&zstm, Z_NO_FLUSH);
			if (ret != Z_OK && ret != Z_STREAM_END) {
				(void)inflateEnd(&zstm);
				perror("inflate");
				return -EINVAL;
			}
			have = sizeof(out) - zstm.avail_out;
			if (ST_INFLATE_HDR == state)
				state = ST_DUMP_HDR;
			else if (ST_INFLATE_NAME == state)
				state = ST_DUMP_NAME;
			else if (ST_INFLATE_DATA == state)
				state = ST_DUMP_DATA;
			else
				state = ST_DONE;/* Don't know how to process futher */
			break;

		case ST_DUMP_HDR:
			if (have < sizeof(hdr)) {
				state = ST_INFLATE_HDR;
				break;
			}
			memcpy(&hdr, p, sizeof(hdr));
			if (opt->flags & FL_DUMP) {
				printf("\n");
				printf("Perm    : %u (%s)\n", hdr.perm, type2name(file_perms_names, hdr.perm));
				printf("Type    : %u (%s)\n", hdr.type, type2name(file_types_names, hdr.type));
				printf("Usr/Grp : %s\n", array2str(hdr.usr_or_grp, sizeof(hdr.usr_or_grp)));
				printf("Time    : %u\n", hdr.time);
				printf("Revision: %u\n", hdr.revision);
				printf("Unknown : %s\n", array2str(hdr.unk_10, sizeof(hdr.unk_10)));
				printf("Ver min : %u\n", hdr.ver_min);
				printf("Ver maj : %u\n", hdr.ver_maj);
				printf("Version2: %s\n", array2str(hdr.ver_2, sizeof(hdr.ver_2)));
				printf("Unknown : %s\n", array2str(hdr.unk_20, sizeof(hdr.unk_20)));
				printf("Data sz : %u\n", hdr.data_size);
				printf("Name len: %u\n", hdr.name_len);
			}
			p += sizeof(hdr);
			have -= sizeof(hdr);
			state = ST_DUMP_NAME;
			break;

		case ST_DUMP_NAME:
			if (have < hdr.name_len) {
				state = ST_INFLATE_NAME;
				break;
			}
			have -= hdr.name_len;
			state = ST_DUMP_DATA;
			tmp = malloc(hdr.name_len + 1);
			if (NULL == tmp) {
				perror("malloc");
				p += hdr.name_len;
				break;
			}
			tmp[hdr.name_len] = '\0';
			strncpy(tmp, (char *)p, hdr.name_len);
			if (opt->flags & FL_DUMP) {
				printf("Name    : %s\n", tmp);
			} else if (opt->flags & FL_LIST) {
				if (NPK_FILE_TYPE_DIR == hdr.type)
					printf("%s%s\n", tmp, tmp[hdr.name_len - 1] != '/' ? "/" : "");
				else
					printf("%s\n", tmp);
			}
			if (opt->op == OP_EXTRACT) {
				if (*(char *)p == '/')
					++tmp;
				if (NPK_FILE_TYPE_DIR == hdr.type) {
					create_path(tmp);
				} else {
					create_file_path(tmp);
					file_out = fopen(tmp, "wb");
					if (NULL == file_out) {
						fprintf(stderr, "open %s: %s\n", tmp, strerror(errno));
						return -1;
					}
				}
				if (*(char *)p == '/')
					--tmp;
			}
			free(tmp);
			p += hdr.name_len;
			break;

		case ST_DUMP_DATA:
			if (have >= hdr.data_size) {
				if (file_out != NULL) {
					if (hdr.data_size != 0 && 1 != fwrite(p, hdr.data_size, 1, file_out)) {
						fclose(file_out);
						fprintf(stderr, "Can't write to the output file.\n");
						return -EIO;
					}
					fclose(file_out);
					file_out = NULL;
				}
				have -= hdr.data_size;
				p += hdr.data_size;
				state = ST_DUMP_HDR;
			} else {
				if (file_out != NULL) {
					if (1 != fwrite(p, have, 1, file_out)) {
						fclose(file_out);
						fprintf(stderr, "Can't write to the output file.\n");
						return -EIO;
					}
				}
				hdr.data_size -= have;
				p += have;
				have = 0;
				state = ST_INFLATE_DATA;
			}
			break;

		case ST_DONE:
			fprintf(stderr, "Invalid file container parser internal state. Interrupt.\n");
			break;
		}
	}

	(void)inflateEnd(&zstm);

	return 0;
}

/**
 * Processes NPK file partition as script (pure text), returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_script(const uint8_t *data, const uint32_t size, const struct options *opt)
{
	if (opt->verb < 2)
		return 0;

	printf("Script:\n%.*s\n", size, data);

	return 0;
}

/**
 * Processes NPK file partition as package architecture, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_pkg_arch(uint8_t *data, const uint32_t size,
				   const struct options *opt)
{
	if ((opt->flags & FL_DUMP) == 0)
		return 0;

	printf("Arch: %.*s\n", size, data);

	return 0;
}

/**
 * Processes NPK file partition as package info, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_pkg_info(uint8_t *data, const uint32_t size,
				   const struct options *opt)
{
	struct npk_part_pkg_info_hdr *hdr = (void *)data;
	char buf[0x80];
	unsigned len;
	struct tm tm;

	len = strnlen(hdr->name, sizeof(hdr->name)) + 1;
	pkg_name = realloc(pkg_name, len);
	if (!pkg_name) {
		perror("realloc");
		return -ENOMEM;
	}
	memcpy(pkg_name, hdr->name, len - 1);
	pkg_name[len - 1] = '\0';

	if ((opt->flags & FL_DUMP) == 0)
		return 0;

	printf("Name      : %s\n", pkg_name);
	printf("Unknown   : %s\n", array2str(hdr->unk_20, sizeof(hdr->unk_20)));
	if (hdr->revision)
		printf("Version   : %u.%u.%u\n", hdr->ver_maj, hdr->ver_min,
		       hdr->revision);
	else
		printf("Version   : %u.%u\n", hdr->ver_maj, hdr->ver_min);
	gmtime_r((time_t *)&hdr->timestamp, &tm);
	strftime(buf, sizeof(buf), "%c", &tm);
	printf("Timestamp : %u (%s)\n", hdr->timestamp, buf);
	printf("Unknown   : %s\n", array2str(hdr->unk_30, sizeof(hdr->unk_30)));

	return 0;
}

/**
 * Processes NPK file partition as SquashFS image, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_squashfs(uint8_t *data, const uint32_t size,
				   const struct options *opt)
{
	char *imgname;
	size_t namelen;
	FILE *fp;
	size_t wres;

	if (opt->flags & FL_DUMP) {
		/* Do nothing */
	} else if (opt->flags & FL_LIST) {
		printf("%s.squashfs\n", pkg_name);
	}

	if (OP_EXTRACT != opt->op)
		return 0;

	/* Name: <pkg_name> + '.squashfs' + '\0' */
	namelen = strlen(pkg_name) + 10;
	imgname = malloc(namelen);
	if (!imgname) {
		perror("malloc");
		return -ENOMEM;
	}
	snprintf(imgname, namelen, "%s.squashfs", pkg_name);

	fp = fopen(imgname, "wb");
	if (!fp) {
		fprintf(stderr, "Error: could not open '%s' for writing: %s\n",
			imgname, strerror(errno));
		free(imgname);
		return -errno;
	}

	wres = fwrite(data, 1, size, fp);
	if (wres != size) {
		fprintf(stderr, "Error: could not write SquashFS data to '%s': %s\n",
			imgname, strerror(errno));
		free(imgname);
		fclose(fp);
		return -errno;
	}

	fclose(fp);
	free(imgname);

	return 0;
}

/**
 * Processes NPK file partition as digest, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_digest(uint8_t *data, const uint32_t size,
				 const struct options *opt)
{
	if ((opt->flags & FL_DUMP) == 0)
		return 0;

	printf("Digest: %.*s\n", size, data);

	return 0;
}

/**
 * Processes NPK file partition as release type, returns zero on success
 * arguments:
 *   * data - Partition data pointer
 *   * size - Partition data size
 *   * opt - Processing options
 */
static int proc_part_data_reltype(uint8_t *data, const uint32_t size,
				  const struct options *opt)
{
	if ((opt->flags & FL_DUMP) == 0)
		return 0;

	printf("Rel. type: %.*s\n", size, data);

	return 0;
}

/**
 * Processes NPK file partition content, returns zero on success
 * arguments:
 *   * type - Partition type
 *   * size - Partition size
 *   * data - Partition data pointer
 *   * opt - Processing options
 */
static int proc_part_data(const uint16_t type, const uint32_t size, uint8_t *data, const struct options *opt)
{
	switch (type) {
	case NPK_PART_PKG_DESC:
		return proc_part_data_pkg_desc(data, size, opt);
	case NPK_PART_INSTALL:
	case NPK_PART_UNINSTALL:
		return proc_part_data_script(data, size, opt);
	case NPK_PART_FILES:
		return proc_part_data_files(data, size, opt);
	case NPK_PART_PKG_ARCH:
		return proc_part_data_pkg_arch(data, size, opt);
	case NPK_PART_PKG_INFO:
	case NPK_PART_PKG_MAIN:
		return proc_part_data_pkg_info(data, size, opt);
	case NPK_PART_SQUASHFS:
		return proc_part_data_squashfs(data, size, opt);
	case NPK_PART_DIGEST:
		return proc_part_data_digest(data, size, opt);
	case NPK_PART_RELTYPE:
		return proc_part_data_reltype(data, size, opt);
	}
	return 0;
}

/* Print main NPK file header */
static void proc_main_print_main_hdr(const struct npk_main_hdr *hdr)
{
	printf("\n[Main header]\n");
	printf("Signature : %s\n", array2str((uint8_t *)&hdr->sign, sizeof(hdr->sign)));
	printf("Remain siz: %u\n", hdr->remain_sz);
}

/* Print NPK file partition header */
static void proc_main_print_part_hdr(const struct npk_part_hdr *hdr)
{
	printf("\n[Partition header]\n");
	printf("Type: %u (%s)\n", hdr->type, type2name(part_types_names, hdr->type));
	printf("Size: %u\n", hdr->size);
}

/**
 * Main NPK processor, returns zero on success
 * arguments:
 *   * base - Base address of file mapping
 *   * opt - Processing options
 */
static int proc_main(uint8_t *base, const struct options *opt)
{
	uint8_t *ptr = base;
	const struct npk_main_hdr *mhdr;
	const struct npk_part_hdr *phdr;
#define REMAIN	(opt->file_in_size - (ptr - base))

	/* Process main header */
	if (sizeof(struct npk_main_hdr) > opt->file_in_size) {
		fprintf(stderr, "Error: File shorter than main header.\n");
		return -EINVAL;
	}
	mhdr = (struct npk_main_hdr *)ptr;
	if (ntohl(mhdr->sign) != NPK_SIGNATURE) {
		fprintf(stderr, "Error: Invalid file signature should be %08X.\n", NPK_SIGNATURE);
		return -EINVAL;
	}
	if (mhdr->remain_sz > (opt->file_in_size - sizeof(mhdr->sign) - sizeof(mhdr->remain_sz)))
		fprintf(stderr, "Warning: remain size header field great than actual file size. File corrupted?");
	else if (mhdr->remain_sz < (opt->file_in_size - sizeof(mhdr->sign) - sizeof(mhdr->remain_sz)))
		fprintf(stderr, "Warning: remain size header field less than actual file size. File corrupted?");
	if (opt->flags & FL_DUMP)
		proc_main_print_main_hdr(mhdr);
	ptr += sizeof(struct npk_main_hdr);

	/* Process file partitions */
	while (REMAIN != 0) {
		if (REMAIN < sizeof(struct npk_part_hdr)) {
			fprintf(stderr, "Error: remain file chunk not enogh for partition header.\n");
			return -EINVAL;
		}
		phdr = (struct npk_part_hdr *)ptr;
		if (opt->flags & FL_DUMP)
			proc_main_print_part_hdr(phdr);
		ptr += sizeof(struct npk_part_hdr);

		if (REMAIN < phdr->size) {
			fprintf(stderr, "Error: remain file chunk not enogh for partition data.\n");
			return -EINVAL;
		} else if (proc_part_data(phdr->type, phdr->size, ptr, opt) != 0)
			return -EINVAL;
		ptr += phdr->size;
	}

#undef REMAIN
	return 0;
}

/* Prints usage information */
static void usage(const char *name)
{
	printf("MikroTik NPK files unpacker/processor v%s.\n", VERSION_STR);
	printf(
		"\n"
		"Usage:\n"
		"  %s {-t|-x} [-v] -f <file> [-C <dir>]\n"
		"  %s -h\n"
		"\n"
		"Options:\n"
		"  -t         List package content\n"
		"  -x         Extract package content\n"
		"  -f <file>  Specify input file name\n"
		"  -C <dir>   Specify output directory for extraction (should exist)\n"
		"  -v         Be verbose (use twice to get full dump)\n"
		"  -h         Show this cruft\n"
		"\n"
		"Examples:\n"
		"  Get full NPK dump:\n"
		"    %s -tvvf routeros-2.7.npk\n"
		"  Silently extract package to the current directory:\n"
		"    %s -xf routeros-2.7.npk\n"
		"  Verbosly extract package to the specified directory:\n"
		"    %s -xvf routeros-2.7.npk -C routeros-2.7\n"
		"\n",
		name, name, name, name, name
	);
	printf("Author: RSA <ryazanov.s.a@gmail.com>\n\n");
}

/**
 * Command line options parser, returns zero on success
 * arguments:
 *   * argc - Arguments number
 *   * argv - Arguments array
 *   * opt - Parsed options (should passed initialized)
 *   * file_in - Pointer to input file name buffer
 */
static int parse_args(const int argc, const char *argv[], struct options *opt)
{
	unsigned i, j;
	enum {
		ST_SEARCH,	/* Search option */
		ST_NEXT_ARG,	/* Select next argument for processing */
		ST_OPT_FILE,	/* Input file argument */
		ST_OPT_DIR,	/* Output directory argument */
	} state;

	for (state = ST_SEARCH, i = 1, j = 0; i < argc; /* Update i & j inside the circle */) {
		/* Process current symbol */
		switch (state) {
		case ST_SEARCH:
			if (0 == j) {
				if (argv[i][0] != '-' || argv[i][1] == '\0') {
					fprintf(stderr, "Unexpected option's argument '%s'.\n", argv[i]);
					return 1;
				}
			} else if ('f' == argv[i][j]) {
				state = ST_OPT_FILE;
			} else if ('C' == argv[i][j]) {
				state = ST_OPT_DIR;
			} else if ('t' == argv[i][j]) {
				opt->op = OP_LIST;
			} else if ('x' == argv[i][j]) {
				opt->op = OP_EXTRACT;
			} else if ('v' == argv[i][j]) {
				++(opt->verb);
			} else if ('h' == argv[i][j]) {
				opt->op = OP_HELP;
			} else {
				fprintf(stderr, "Unknown option '%c'.\n", argv[i][j]);
				return 1;
			}
			break;

		case ST_OPT_FILE:
			opt->file_in = &argv[i][j];
			state = ST_NEXT_ARG;
			break;

		case ST_OPT_DIR:
			opt->dir_out = &argv[i][j];
			state = ST_NEXT_ARG;
			break;

		default:
			fprintf(stderr, "Arg parser state machine internal error.\n");
			return 1;
		}

		/* Update indexes */
		if (ST_NEXT_ARG == state || '\0' == argv[i][j + 1]) {
			++i;
			j = 0;
			if (ST_NEXT_ARG == state)
				state = ST_SEARCH;
		} else {
			++j;
		}
	}
	if (state != ST_SEARCH) {
		fprintf(stderr, "Option '%c' require an argument.\n", argv[i - 1][strlen(argv[i]) - 1]);
		return 1;
	}

	return 0;
}

/* NPK processor entry point */
int main(const int argc, const char *argv[])
{
	const char *name;
	struct options opt;
	int fd, ret;
	struct stat sb;
	uint8_t *base;

	name = strrchr(argv[0], '/');
	name = NULL == name ? argv[0] : name + 1;

	memset(&opt, 0x00, sizeof(opt));

	if (argc == 1) {
		usage(name);
		return 0;
	} else if (parse_args(argc, argv, &opt) != 0) {
		return 1;
	} else if (OP_HELP == opt.op) {
		usage(name);
		return 0;
	} else if (NULL == opt.file_in) {
		fprintf(stderr, "You should specify input file.\n");
		return 1;
	} else if (OP_UNKNOWN == opt.op) {
		fprintf(stderr, "You should specify operation.\n");
		return 1;
	}

	if (OP_EXTRACT == opt.op) {
		if (opt.verb > 1)
			opt.flags |= FL_DUMP;
		else if (opt.verb > 0)
			opt.flags |= FL_LIST;
	} else if (OP_LIST == opt.op) {
		if (opt.verb > 0)
			opt.flags |= FL_DUMP;
		else
			opt.flags |= FL_LIST;
	}

	fd = open(opt.file_in, O_RDONLY);
	if (-1 == fd) {
		fprintf(stderr, "open %s: %s\n", opt.file_in, strerror(errno));
		return 1;
	}

	if (fstat(fd, &sb) == -1) {
		fprintf(stderr, "stat %s: %s\n", opt.file_in, strerror(errno));
		close(fd);
		return 1;
	}

	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s is not regular file.\n", opt.file_in);
		close(fd);
		return 1;
	}
	opt.file_in_size = sb.st_size;

	base = mmap(0, opt.file_in_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == base) {
		perror("mmap");
		close(fd);
		return 1;
	}

	if (close(fd) == -1) {
		perror("close");
		return 1;
	}

	if (OP_EXTRACT == opt.op && opt.dir_out != NULL) {
		if (chdir(opt.dir_out) != 0) {
			fprintf(stderr, "chdir %s: %s\n", opt.dir_out, strerror(errno));
			return 1;
		}
	}

	pkg_name = strdup("unknown-pkg");

	ret = proc_main(base, &opt);

	if (munmap(base, opt.file_in_size) == -1) {
		perror("munmap");
		return 1;
	}

	return 0 == ret ? 0 : 1;
}
