/*
 * Macher is a command line tool for inspecting and modifying Mach-O binary files
 * as produced by Apple's clang C compiler.
 *
 * Copyright © 2021 Marc Culler
 *
 * Macher is open source software distributed under a Simplified BSD License.
 * See the file License.txt included with the source code distribution.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/fat.h>
#include <mach/mach.h>
#include "macher.h"
#define MAJOR(x) ((x >> 16) & 0xff)
#define MINOR(x) ((x >> 8) & 0xff)
#define PATCH(x) (x & 0xff)

typedef struct {
    bool reversed;
    unsigned long position;
    struct load_command lc;
    void *data;
} mach_o_command;

typedef struct {
    bool verbose;
    bool reverse_bytes;
    bool is_64bit;
    char *path;
    char *mode;
    FILE *mach_o_file;
    int header_size;
    void *header_data;
    uint32_t filetype;
    int num_commands;
    int command_block_size;
    unsigned long command_space;
    mach_o_command *commands;
} mach_o_obj;

static void swap_data_bytes(mach_o_obj *mach_o, mach_o_command *command);
static int  aligned_command_size(mach_o_obj *mach_o, int min_size);
static void update_header(mach_o_obj *mach_o);
static void compute_command_space(mach_o_obj *mach_o);
static bool find_rpath(mach_o_obj *mach_o, char *rpath);
static void remove_command(mach_o_obj *mach_o, int index);
static void init_mach_o(mach_o_obj *mach_o, char *path, char *mode);
static void destroy_mach_o(mach_o_obj *mach_o);
static void usage();
extern void append_data(char *mach_path, char *data_path, char *output_path);

/* actions */
static int print_command(mach_o_obj *mach_o, mach_o_command *command, char *arg);
static int print_segment(mach_o_obj *mach_o, mach_o_command *command, char *arg);
static int XXappend_data(mach_o_obj *mach_o, mach_o_command *command, char *data_path);
static int add_rpath(mach_o_obj *mach_o, mach_o_command *command, char *rpath);
static int remove_rpath(mach_o_obj *mach_o, mach_o_command *command, char *rpath);
static int edit_libpath(mach_o_obj *mach_o, mach_o_command *command, char *libpath);

static void init_mach_o(mach_o_obj *mach_o, char *path, char *mode)
{
    uint32_t magic;
    struct load_command lc;
    mach_o_command mc;

    mach_o->path = path;
    mach_o->mach_o_file = fopen(mach_o->path, mode);
    if (! mach_o->mach_o_file) {
	printf("Could not open mach-o file %s\n", mach_o->path);
	exit(1);
    }
    /*
     * Read the magic number to figure out which type of Mach-O file we have.
     */
    fread(&magic, sizeof(uint32_t), 1, mach_o->mach_o_file);
    switch (magic) {
    case FAT_MAGIC:
    case OSSwapInt32(FAT_MAGIC):
	printf("Fat binaries are not supported.  Use\n"
	       "    lipo <fat file> -thin <arch> -output <thin file>\n"
	       "to create single-architecture binaries.\n");
	exit(1);
    case MH_MAGIC_64:
	mach_o->is_64bit = true;
	mach_o->reverse_bytes = false;
	break;
    case MH_MAGIC:
	mach_o->is_64bit = false;
	mach_o->reverse_bytes = false;
	break;
    case OSSwapInt32(MH_MAGIC_64):
	mach_o->is_64bit = true;
	mach_o->reverse_bytes = true;
	break;
    case OSSwapInt32(MH_MAGIC):
	mach_o->is_64bit = true;
	mach_o->reverse_bytes = false;
	break;
    default:
	printf("error: The binary is not a mach-O file.\n");
	exit(1);
	}
    if (mach_o->verbose) {
	struct stat st;
	stat(mach_o->path, &st);
	printf("The Mach-O magic number is 0x%x.\n", magic);
	printf("The Mach-O file size is %llu.\n", st.st_size);
    }
    /*
     * Read the Mach-O header.
     */
    fseek(mach_o->mach_o_file, 0L, SEEK_SET);
    if (mach_o->is_64bit) {
	struct mach_header_64 *header;
	mach_o->header_size = sizeof(struct mach_header_64);
	mach_o->header_data = malloc(mach_o->header_size);
	header = (struct mach_header_64 *) mach_o->header_data;
	fread(mach_o->header_data, mach_o->header_size, 1, mach_o->mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_mach_header_64(header, 0);
	}
	mach_o->filetype = header->filetype;
	mach_o->num_commands = header->ncmds;
	mach_o->command_block_size = header->sizeofcmds;
	if (mach_o->verbose) {
	    printf("The Mach-O header occupies %d bytes\n", mach_o->header_size);
	    printf("Currently %u bytes are being used to store %u load commands.\n",
		   header->sizeofcmds, header->ncmds);
	}
    } else {
	struct mach_header *header;
	mach_o->header_size = sizeof(struct mach_header);
	mach_o->header_data = malloc(mach_o->header_size);
	header = (struct mach_header *) mach_o->header_data;
	fread(mach_o->header_data, mach_o->header_size, 1, mach_o->mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_mach_header(header, 0);
	}
	mach_o->filetype = header->filetype;
	mach_o->num_commands = header->ncmds;
	mach_o->command_block_size = header->sizeofcmds;
	if (mach_o->verbose) {
	    printf("%u bytes are being used to store %u load commands.\n",
		   header->sizeofcmds, header->ncmds);
	}
    }
    /*
     * Copy all of the load commands into memory.  We may add at most one new
     * command, so we allocate space for one extra.
     */
    mach_o->commands = (mach_o_command *) malloc(
	sizeof(mach_o_command) * (1 + mach_o->num_commands));
    fseek(mach_o->mach_o_file, mach_o->header_size, SEEK_SET);
    for (int i = 0; i < mach_o->num_commands; i++) {
	long pos = ftell(mach_o->mach_o_file);
	fread(&lc, sizeof(struct load_command), 1, mach_o->mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_load_command(&lc, 0);
	}
	mc.reversed = false;
	mc.position = pos;
	mc.lc = lc;
	mc.data = malloc(lc.cmdsize);
	fseek(mach_o->mach_o_file, pos, SEEK_SET);
	fread(mc.data, lc.cmdsize, 1, mach_o->mach_o_file);
	swap_data_bytes(mach_o, &mc);
	mach_o->commands[i] = mc;
    }
    /*
     * Check how much space is available in the file for commands.
     */
    compute_command_space(mach_o);
}

static void destroy_mach_o(mach_o_obj *mach_o)
{
    for (int i = 0; i < mach_o->num_commands; i++) {
	mach_o_command *command = mach_o->commands + i;
	free(command->data);
    }
    free(mach_o->header_data);
    mach_o->header_data = NULL;
    free(mach_o->commands);
    mach_o->commands = NULL;
    fclose(mach_o->mach_o_file);
}

static int aligned_command_size(mach_o_obj *mach_o, int min_size)
{
    if (mach_o->is_64bit) {
	return (min_size + 15) & ~15;
    } else {
	return (min_size + 7) + ~7;
    }
}

static void swap_data_bytes(mach_o_obj *mach_o, mach_o_command *command)
{
    /*
     * Don't do anything to commands that we don't change.
     */
    if (!mach_o->reverse_bytes) {
	return;
    }
    switch (command->lc.cmd) {
    case LC_SEGMENT:
	{
	    struct segment_command *seg = (struct segment_command *) command->data;
	    struct section *section = (struct section *)
		(command->data + sizeof(struct segment_command));
	    swap_segment_command(seg, 0);
	    if(seg->nsects != 0){
		swap_section(section, seg->nsects, 0);
	    }
	    command->reversed = !command->reversed;
	    break;
	}
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *seg = (struct segment_command_64 *) command->data;
	    struct section_64 *section = (struct section_64 *)
		(command->data + sizeof(struct segment_command_64));
	    swap_segment_command_64(seg, 0);
	    if(seg->nsects != 0){
		swap_section_64(section, seg->nsects, 0);
	    }
	    command->reversed = !command->reversed;
	    break;
	}
    case LC_SYMTAB:
	{
	    struct symtab_command *st = (struct symtab_command *) command->data;
	    swap_symtab_command(st, 0);
	    command->reversed = !command->reversed;
	    break;
	}
    }
}

static void update_header(mach_o_obj *mach_o)
{
    if (mach_o->is_64bit) {
	struct mach_header_64 *header = (struct mach_header_64 *)
	    mach_o->header_data;
	header->ncmds = mach_o->num_commands;
	header->sizeofcmds = mach_o->command_block_size;
	fseek(mach_o->mach_o_file, 0, SEEK_SET);
	if (mach_o->reverse_bytes) {
	    swap_mach_header_64(header, 0);
	    fwrite(mach_o->header_data, sizeof(struct mach_header_64), 1,
		   mach_o->mach_o_file);
	    swap_mach_header_64(header, 0);
	} else {
	    fwrite(mach_o->header_data, sizeof(struct mach_header_64), 1,
		   mach_o->mach_o_file);
	}
    } else {
	struct mach_header *header = (struct mach_header *)
	    mach_o->header_data;
	header->ncmds = mach_o->num_commands;
	header->sizeofcmds = mach_o->command_block_size;
	fseek(mach_o->mach_o_file, 0, SEEK_SET);
	if (mach_o->reverse_bytes) {
	    swap_mach_header(header, 0);
	    fwrite(mach_o->header_data, sizeof(struct mach_header), 1,
		   mach_o->mach_o_file);
	    swap_mach_header(header, 0);
	} else {
	    fwrite(mach_o->header_data, sizeof(struct mach_header), 1,
		   mach_o->mach_o_file);
	}
	    
    }
}

static void remove_command(mach_o_obj *mach_o, int index)
{
    mach_o_command *command = mach_o->commands + index;
    int command_size = command->lc.cmdsize;
    int tail_size = mach_o->command_space - command->position - command_size;
    char *buffer = malloc(tail_size);
    char null = '\0';
    fseek(mach_o->mach_o_file, command->position + command_size, SEEK_SET);
    fread(buffer, tail_size, 1, mach_o->mach_o_file);
    fseek(mach_o->mach_o_file, command->position, SEEK_SET);
    fwrite(buffer, tail_size, 1, mach_o->mach_o_file);
    fwrite(&null, 1, command_size, mach_o->mach_o_file);
    free(command->data);
    for (int i = index; i < mach_o->num_commands - 1; i++) {
	mach_o->commands[i] = mach_o->commands[i + 1];
    }
    mach_o->num_commands -= 1;
    mach_o->command_block_size -= command_size;
    mach_o->command_space += command_size;
    update_header(mach_o);
}

static void compute_command_space(mach_o_obj *mach_o)
{
    int command_space = -1;
    for (int i = 0; i < mach_o->num_commands; i++) {
	mach_o_command *command = mach_o->commands + i;
	if (command->lc.cmd == LC_SEGMENT_64) {
	    struct segment_command_64 *seg = (struct segment_command_64 *)
		command->data;
	    if (!strcmp(seg->segname, "__TEXT")) {
		struct section_64 *section = (struct section_64 *)
		    (command->data + sizeof(struct segment_command_64));
		command_space = section->offset;
		for (int i = 1; i < seg->nsects; i++){
		    if (section->offset < command_space) {
			command_space = section->offset;
		    }
		    section++;
		}
		break;
	    }
	} else if (command->lc.cmd == LC_SEGMENT) {
	    struct segment_command *seg = (struct segment_command *)
		command->data;
	    if (!strcmp(seg->segname, "__TEXT")) {
		struct section *section = (struct section *)
		    ((char *)seg + sizeof(struct segment_command));
		command_space = section->offset;
		for (int i = 1; i < seg->nsects; i++){
		    if (section->offset < command_space) {
			command_space = section->offset;
		    }
		    section++;
		}
		break;
	    }
	}

    }
    if (command_space >= 0) {
	mach_o->command_space = command_space;
	if (mach_o->verbose) {
	    printf("A total of %lu bytes are available for storing load commands.\n\n",
		   mach_o->command_space);
	}
    } else {
	mach_o->command_space = 0;
    }
}

static bool find_rpath(mach_o_obj *mach_o, char *rpath)
{
    for (int i = 0; i < mach_o->num_commands; i++) {
	mach_o_command *command = mach_o->commands + i;
	if (command->lc.cmd == LC_RPATH) {
	    struct rpath_command *rp = (struct rpath_command *) command->data;
	    char *command_rpath = (char *) rp + rp->path.offset;
	    if (!strcmp(rpath, command_rpath)) {
	    	return true;
	    }
	}
    }
    return false;
}

static int print_command(mach_o_obj *mach_o, mach_o_command *command, char *arg)
{
    int command_id = command->lc.cmd & ~LC_REQ_DYLD;
    switch (command_id) {
    case LC_SEGMENT:
	{
	    struct segment_command *seg =
		(struct segment_command *)command->data;
	    printf("LC_SEGMENT %s [%u : %u]\n", seg->segname, seg->fileoff,
		   seg->fileoff + seg->filesize);
	    if (mach_o->verbose) {
		struct section *section = (struct section *)
		    ((char *)seg + sizeof(struct segment_command));
		if(seg->nsects != 0){
		    for(int i = 0; i < seg->nsects; i++){
			printf("    Section %s [%u : %u ]\n", section->sectname,
			       section->offset, section->offset + section->size);
			section++;
		    }
		} else {
		    printf("    No sections\n");
		}
	    }
	}
	break;
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *seg = (struct segment_command_64 *)
		command->data;
	    printf("LC_SEGMENT_64 %s [%llu : %llu]\n", seg->segname, seg->fileoff,
		   seg-> fileoff + seg->filesize);
	    if (mach_o->verbose) {
		struct section_64 *section = (struct section_64 *)
		    ((char *)seg + sizeof(struct segment_command_64));
		if(seg->nsects != 0){
		    for(int i = 0; i < seg->nsects; i++){
			printf("    Section %s [%u : %llu ]\n", section->sectname,
			       section->offset, section->offset + section->size);
			section++;
		    }
		} else {
		    printf("    No sections\n");
		}
	    }
	}
	break;
    case LC_ID_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("LC_ID_DYLIB: %s\n",
		   (char *)command->data + dl->dylib.name.offset);
	}
	break;
    case LC_LOAD_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("LC_LOAD_DYLIB: %s\n",
		   (char *) command->data + dl->dylib.name.offset);
	}
	break;
    case LC_UUID:
	{
	    struct uuid_command *uu = (struct uuid_command *)command->data;
	    char uuid[37];
	    uuid[0] = '\0';
	    uuid_unparse(uu->uuid, uuid);
	    printf("LC_UUID: %s\n", uuid);
	}
	break;
    case LC_SYMTAB:
	{
	    struct symtab_command *tab = (struct symtab_command *)command->data;
	    printf("LC_SYMTAB: offset is %d, %u symbols, strings in [%d : %d]\n",
		   tab->symoff, tab->nsyms, tab->stroff,
		   tab->stroff + tab->strsize);
	}
	break;
    case LC_RPATH & ~LC_REQ_DYLD:
	{
	    struct rpath_command *rp = (struct rpath_command *)command->data;
	    printf("LC_RPATH: %s\n", (char *) rp + rp->path.offset);
	}
	break;
    case LC_DYLD_INFO:
	{
	    printf("%s%s\n", "LC_DYLD_INFO",
		   (command->lc.cmd & LC_REQ_DYLD) != 0 ? "_ONLY" : "");
	}
	break;
    case LC_BUILD_VERSION:
	{
	    struct build_version_command *version =
		(struct build_version_command *)command->data;
	    int min = version->minos;
	    int sdk = version->sdk;
	    printf("LC_BUILD_VERSION: min = %d.%d.%d, sdk = %d.%d.%d\n",
		   MAJOR(min), MINOR(min), PATCH(min), MAJOR(sdk), MINOR(sdk),
		   PATCH(sdk));
	}
	break;
    case LC_SOURCE_VERSION:
	{
	    struct source_version_command *version =
		(struct source_version_command *)command->data;
	    unsigned long long packed = version->version;
	    int parts[5];
	    for (int i = 0; i < 4; i++) {
		parts[i] = packed & 0x3ff;
		packed = packed >> 10;
	    }
	    parts[4] = packed;
	    printf("LC_SOURCE_VERSION: %d.%d.%d.%d.%d\n", parts[4], parts[3], parts[2],
		   parts[1], parts[0]);
	}
	break;
    case LC_VERSION_MIN_MACOSX:
	{
	    struct version_min_command *version =
		(struct version_min_command *)command->data;
	    int min = version->version;
	    int sdk = version->sdk;
	    printf("LC_VERSION_MIN_MACOSX: min = %d.%d.%d, sdk = %d.%d.%d\n",
		   MAJOR(min), MINOR(min), PATCH(min), MAJOR(sdk), MINOR(sdk),
		   PATCH(sdk));
	}
	break;
    default:
	if (command_id < num_load_commands) {
	    printf("%s\n", load_command_names[command_id]);
	} else {
	    printf("Invalid command id %d.\n", command_id);
	    exit(1);
	}
	break;
    }
    return 0;
}

static int print_segment(mach_o_obj *mach_o, mach_o_command *command, char *arg)
{
    if (command->lc.cmd == LC_SEGMENT || command->lc.cmd == LC_SEGMENT_64) {
	print_command(mach_o, command, arg);
    }
    return 0;
}

static int XXappend_data(mach_o_obj *mach_o, mach_o_command *command, char *data_path)
{
    /*
     * When appending data we need to change values in two of the load commands but
     * the size of the commands does not change.  So we just overwrite the commands
     * in the file and then append the data.
     */
    struct stat st;
    unsigned long data_size;
    FILE *mach_o_file, *data_file;

    if (stat(data_path, &st)) {
	printf("Could not find data file %s.\n", data_path);
	exit(1);
    }
    data_size = st.st_size;
    switch (command->lc.cmd & ~LC_REQ_DYLD) {
    case LC_SEGMENT:
	{
	    struct segment_command *segment = (struct segment_command *) command->data;
	    if (!strcmp(segment->segname, "__LINKEDIT")) {
		if (mach_o->verbose) {
		    printf("Extending linkedit segment by %lu bytes.\n", data_size);
		}
		segment->filesize += data_size;
	    }
	    break;
	}
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *segment = (struct segment_command_64 *) command->data;
	    if (!strcmp(segment->segname, "__LINKEDIT")) {
		if (mach_o->verbose) {
		    printf("Extending linkedit segment by %lu bytes.\n", data_size);
		}
		segment->filesize += data_size;
		fseek(mach_o->mach_o_file, command->position, SEEK_SET);
		int n = fwrite(command->data, command->lc.cmdsize, 1, mach_o->mach_o_file);
	    }
	    break;
	}
    case LC_SYMTAB:
	{
	    char buffer[512];
	    FILE *data_file;
	    int count = 0;
	    struct symtab_command *symtab = (struct symtab_command *) command->data;
	    if (mach_o->verbose) {
		printf("Extending symtab string block by %lu bytes.\n", data_size);
	    }
	    symtab->strsize += data_size;
	    fseek(mach_o->mach_o_file, command->position, SEEK_SET);
	    fwrite(command->data, command->lc.cmdsize, 1, mach_o->mach_o_file);
	    if (mach_o->verbose) {
		printf("Appending %lu bytes of data.\n", data_size);
	    }
	    fclose(mach_o->mach_o_file);
	    mach_o->mach_o_file = fopen(mach_o->path, "a");
	    data_file = fopen(data_path, "r");
	    while (!feof(data_file)) {
		count = fread(buffer, 1, 512, data_file);
		fwrite(buffer, count, 1L, mach_o->mach_o_file);
	    }
	    fclose(data_file);
	}
    }
    return 0;
}

static int add_rpath(mach_o_obj *mach_o, mach_o_command *command, char *rpath)
{
    mach_o_command *mc = mach_o->commands + mach_o->num_commands;
    struct rpath_command *rc;
    int min_size = sizeof(struct rpath_command) + strlen(rpath) + 1;
    int command_size = aligned_command_size(mach_o, min_size);
    if (command_size + mach_o->command_block_size > mach_o->command_space) {
	printf("There is not enough space in the file for another RPATH.\n");
	exit(1);
    }
    if (mach_o->verbose) {
	printf("Adding rpath %s\n", rpath);
    }
    mc->lc.cmd = LC_RPATH;
    mc->lc.cmdsize = command_size;
    mc->reversed = false;
    mc->position = mach_o->header_size + mach_o->command_block_size;
    mc->data = calloc(command_size, 1);
    rc = (struct rpath_command *) mc->data;
    rc->cmd = mc->lc.cmd;
    rc->cmdsize = mc->lc.cmdsize;
    rc->path.offset = sizeof(struct rpath_command);
    strcpy((char *) mc->data + rc->path.offset, rpath);
    mach_o->num_commands += 1;
    mach_o->command_block_size += command_size;
    mach_o->command_space -= command_size;
    fseek(mach_o->mach_o_file, mc->position, SEEK_SET);
    int count = fwrite((char *) mc->data, 1, command_size, mach_o->mach_o_file);
    update_header(mach_o);
    return 1;
}

static int remove_rpath(mach_o_obj *mach_o, mach_o_command *command, char *rpath)
{
    if (command->lc.cmd == LC_RPATH) {
	struct rpath_command *rp = (struct rpath_command *) command->data;
	char *command_path = (char *) rp + rp->path.offset;
	if (!strcmp(rpath, command_path)) {
	    if (mach_o->verbose) {
		printf("Removed RPATH load command for %s\n", rpath);
	    }
	    remove_command(mach_o, command - mach_o->commands);
	}
    }
    return 0;
}

static void change_dylib_path(mach_o_obj *mach_o, mach_o_command *command, char *path)
{
    int index = command - mach_o->commands;
    struct dylib_command *dc = (struct dylib_command *) command->data;
    char *old_path = (char *) dc + dc->dylib.name.offset;
    struct dylib_command *new_command;
    int old_size = command->lc.cmdsize;
    int min_size = old_size + strlen(path) - strlen(old_path);
    int new_size = aligned_command_size(mach_o, min_size);
    int delta = new_size - old_size;
    char *tail;
    int tail_size = mach_o->command_space - command->position - old_size;
    if (mach_o->command_block_size + delta > mach_o->command_space) {
	printf("There is not enough space in the file to change the id.\n");
	exit(1);
    }
    tail = malloc(tail_size);
    fseek(mach_o->mach_o_file, command->position + old_size, SEEK_SET);
    fread(tail, tail_size, 1, mach_o->mach_o_file);
    fseek(mach_o->mach_o_file, command->position, SEEK_SET);
    command->data = calloc(new_size, 1);
    command->lc.cmdsize = new_size;
    new_command = (struct dylib_command *) command->data;
    *new_command = *dc;
    new_command->cmdsize = new_size;
    strcpy((char *)new_command + new_command->dylib.name.offset, path);
    fwrite(command->data, new_size, 1, mach_o->mach_o_file);
    fwrite(tail, tail_size, 1, mach_o->mach_o_file);
    free(tail);
    for (int i = index; i < mach_o->num_commands; i++) {
	mach_o->commands[i].position += delta;
    }
    mach_o->command_block_size += delta;
    mach_o->command_space -= delta;
    update_header(mach_o);
    free(dc);
}
	
static int edit_libpath(mach_o_obj *mach_o, mach_o_command *command, char *libpath)
{
    char *old_libpath, *old_libname;
    char libname[strlen(basename(libpath)) + 1];
    struct dylib_command *dc;

    if (command->lc.cmd != LC_LOAD_DYLIB) {
	if (command - mach_o->commands == mach_o->num_commands - 1) {
	    printf("No LC_LOAD_DYLIB command matches %s.\n", basename(libpath));
	}
	return 0;
    }
    strcpy(libname, basename(libpath));
    dc = (struct dylib_command *) command->data;
    old_libpath = (char *) dc + dc->dylib.name.offset;
    old_libname = basename(old_libpath);
    if (strcmp(libname, old_libname) == 0) {
	change_dylib_path(mach_o, command, libpath);
	return 1;
    } else {
	return 0;
    }
}

static int set_id(mach_o_obj *mach_o, mach_o_command *command, char *idpath)
{
    if (command->lc.cmd != LC_ID_DYLIB) {
	return 0;
    }
    change_dylib_path(mach_o, command, idpath);
    return 1;
}

static void usage()
{
    printf("Usage: \n");
    printf("    mach_o [-v|--verbose] help\n");
    printf("    mach_o [-v|--verbose] version\n");
    printf("    mach_o [-v|--verbose] segments <mach-O file>\n");
    printf("    mach_o [-v|--verbose] commands <mach-O file>\n");
    printf("    mach_o [-v|--verbose] append <mach-O file> <data file> <output>\n");
    printf("    mach_o [-v|--verbose] add_rpath <library dir> <Mach-O file path>\n");
    printf("    mach_o [-v|--verbose] remove_rpath <library dir> <Mach-O file path>\n");
    printf("    mach_o [-v|--verbose] set_libpath <library path> <Mach-O file path>\n");
    printf("    mach_o [-v|--verbose] set_id <library path> <Mach-O file path>\n");
    exit(1);
}

typedef int (*action_op)(mach_o_obj *mach_o, mach_o_command *command, char *arg);

typedef enum {HELP=1, VERSION, SEGMENTS, COMMANDS, APPEND, ADD_RPATH, REMOVE_RPATH,
	      EDIT_LIBPATH, SET_ID} action_id;

typedef struct {
    action_id id;
    char *name;
    action_op op;
} mach_o_action;

static mach_o_action actions[] = {
    {.id = HELP, .name = "help", .op = NULL},
    {.id = VERSION, .name = "version", .op = NULL},
    {.id = COMMANDS, .name = "commands", .op = print_command},
    {.id = SEGMENTS, .name = "segments", .op = print_segment},
    {.id = APPEND, .name = "append", .op = NULL},
    {.id = ADD_RPATH, .name = "add_rpath", .op = add_rpath},
    {.id = REMOVE_RPATH, .name = "remove_rpath", .op = remove_rpath},
    {.id = EDIT_LIBPATH, .name = "edit_libpath", .op = edit_libpath},
    {.id = SET_ID, .name = "set_id", .op = set_id},
    {0}
};

int main(int argc, char **argv)
{
    mach_o_obj mach_o = {0}; /* This is a singleton, so we can store it on the stack. */
    char *mach_o_path;
    static int verbose_flag;
    int option_index = 0;
    char *command;
    mach_o_action action = {0};
    char *mode, *mach_path, *data_path, *output_path, *action_arg;

    while (1) {
    int c;
      static struct option long_options[] =
        {
          {"verbose", no_argument, &verbose_flag, 1},
          {0, 0, 0, 0}
        };
      c = getopt_long (argc, argv, "v", long_options, &option_index);
      if (c == -1)
        break;
      switch (c)
        {
        case 0:
          if (long_options[option_index].flag != 0)
            break;
        case 'v':
          verbose_flag = 1;
          break;
        case '?':
          break;
        default:
          abort ();
        }
    }
    if (verbose_flag) {
	mach_o.verbose = true;
    }
    if (optind >= argc) {
	usage();
    }
    command = argv[optind++];
    for (mach_o_action *a = actions; a->id != 0; a++) {
	if (strcmp(a->name, command) == 0) {
	    action = *a;
	    break;
	}
    }
    switch(action.id) {
    case HELP:
	usage();
	break;
    case VERSION:
	printf("This is version 1.0 of macher.\n");
	exit(0);
    case APPEND:
	if (argc != optind + 3) {
	    usage();
	}
	mach_path = argv[optind++];
	data_path = argv[optind++];
	output_path = argv[optind];
	append_data(mach_path, data_path, output_path);
	return 0;
    case ADD_RPATH:
    case REMOVE_RPATH:
    case EDIT_LIBPATH:
    case SET_ID:
	if (argc != optind + 2) {
	    usage();
	}
	mode = "r+";
	action_arg = argv[optind++];
	mach_path = argv[optind];
	break;
    default:
	if (argc != optind + 1) {
	    usage();
	}
	mode = "r";
	mach_path = argv[optind];
	action_arg = NULL;
	break;
    }
    init_mach_o(&mach_o, mach_path, mode);
    if ((action.id == ADD_RPATH) && find_rpath(&mach_o, action_arg)) {
	printf("An RPATH load command for %s already exists.\n", action_arg);
	exit(1);
    }
    if ((action.id == REMOVE_RPATH) && !find_rpath(&mach_o, action_arg)) {
	printf("No RPATH load command for %s exists.\n", action_arg);
	exit(1);
    }
    if ((action.id == SET_ID) && (mach_o.filetype != MH_DYLIB)) {
	printf("The dylib id can only be set for a dylib file.\n");
	exit(1);
    }

    if (action.op) {
	for (int i = 0; i < mach_o.num_commands; i++) {
	    if (action.op(&mach_o, mach_o.commands + i, action_arg)) {
		break;
	    }
	}
    }
    destroy_mach_o(&mach_o);
    return 0;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 79
 * coding: utf-8
 * End:
 */
