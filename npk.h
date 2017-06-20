/**
 * Mikrotik's NPK file structures definitions
 *
 * Copyright (c) 2012-2017, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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

/* Main NPK file header */
struct npk_main_hdr {
	uint32_t sign;				/* File magic signature */
	uint32_t remain_sz;			/* Remain file size */
} __attribute__((packed));

/* NPK partition types */
#define NPK_PART_PKG_INFO	0x01	/* Package information: name, ver, etc. */
#define NPK_PART_PKG_DESC	0x02	/* Package description */
#define NPK_PART_FILES		0x04	/* Files container */
#define NPK_PART_INSTALL	0x07	/* Install script */
#define NPK_PART_UNINSTALL	0x08	/* Uninstall script */
#define NPK_PART_PKG_ARCH	0x10	/* Package architecture (e.g. i386) */
#define NPK_PART_PKG_MAIN	0x12	/* Main package info: name, version, etc. */
#define NPK_PART_SQUASHFS	0x15	/* SquashFS image */
#define NPK_PART_DIGEST		0x17	/* Digest */
#define NPK_PART_RELTYPE	0x18	/* Release type (e.g. stable, bugfix) */

/* NPK partition header */
struct npk_part_hdr {
	uint16_t type;			/* Partition type (see above) */
	uint32_t size;			/* Partition size */
} __attribute__((packed));

/* Length of package name field */
#define NPK_PKG_NAME_LEN	16

/* NPK package main info */
struct npk_part_pkg_info_hdr {
	char name[NPK_PKG_NAME_LEN];	/* Package name */
	uint8_t revision;		/* Revision */
	uint8_t unk_20[1];		/* Unknown field */
	uint8_t ver_min;		/* Version minor */
	uint8_t ver_maj;		/* Version major */
	uint32_t timestamp;		/* Timestamp */
	uint8_t unk_30[8];		/* Unknown field */
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
