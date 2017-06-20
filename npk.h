/**
 * Mikrotik's NPK file structures definitions
 *
 * Copyright (c) 2012, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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

/**
 * Referencies:
 *  - http://routing.explode.gr/node/96
 */

#ifndef _NPK_H_
#define _NPK_H_

#include <stdint.h>

/* NPK file signature */
#define NPK_SIGNATURE	0x1EF1D0BA

/* Length of name field of main NPK header */
#define NPK_MAIN_HDR_NAME_LEN	16

/* Main NPK file header */
struct npk_main_hdr {
	uint32_t sign;				/* File magic signature */
	uint32_t remain_sz;			/* Remain file size */
	uint8_t unk_10[6];			/* Unknown field */
	char name[NPK_MAIN_HDR_NAME_LEN];	/* NPK name */
	uint8_t revision;			/* Revision */
	uint8_t unk_20[1];			/* Unknown field */
	uint8_t ver_min;			/* Version minor */
	uint8_t ver_maj;			/* Version major */
	uint32_t timestamp;			/* Timestamp */
	uint8_t unk_30[10];			/* Unknown field */
	uint8_t unk_40[4];			/* Unknown field */
	char arch[4];				/* Arch string */
	uint8_t unk_50[2];			/* Unknown field */
	uint32_t descr_len;			/* Description size */
} __attribute__((packed));

/* NPK partition types */
#define NPK_PART_FILES		4	/* Files container */
#define NPK_PART_INSTALL	7	/* Install script */
#define NPK_PART_UNINSTALL	8	/* Uninstall script */

/* NPK partition header */
struct npk_part_hdr {
	uint16_t type;			/* Partition type (see above) */
	uint32_t size;			/* Partition size */
} __attribute__((packed));

#define NPK_FILE_PERM_EXEC	237	/* Executable */
#define NPK_FILE_PERM_NOTEXEC	164	/* Not executable */

#define NPK_FILE_TYPE_DEV	33	/* Device node */
#define NPK_FILE_TYPE_DIR	65	/* Directory */
#define NPK_FILE_TYPE_REGULAR	129	/* Regular file */

/* NPK file container item header */
struct npk_part_file_item_hdr {
	uint8_t perm;			/* File permission */
	uint8_t type;			/* File type */
	uint8_t usr_or_grp[6];		/* User or group */
	uint32_t time;			/* Last modification time */
	uint8_t revision;		/* Revision */
	uint8_t unk_10[1];		/* Unknown field */
	uint8_t ver_min;		/* Version minor */
	uint8_t ver_maj;		/* Version major */
	uint8_t ver_2[4];		/* Version 2 */
	uint8_t unk_20[4];		/* Unknown field */
	uint32_t data_size;		/* File data size */
	uint16_t name_len;		/* File name size */
} __attribute__((packed));

#endif	/* !_NPK_H_ */
