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
#define MACHER_VERSION "1.3"

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
#include <mach-o/arch.h>
#include <mach/mach.h>
#include "macher.h"
#define MAJOR(x) ((x >> 16) & 0xff)
#define MINOR(x) ((x >> 8) & 0xff)
#define PATCH(x) (x & 0xff)

static char zero = 0;

typedef struct {
    bool reversed;
    unsigned long position;
    struct load_command lc;
    void *data;
} mach_o_command;

typedef struct slice {
    bool verbose;
    int offset;
    bool reverse_bytes;
    bool is_64bit;
    FILE *mach_o_file;
    int header_size;
    void *header_data;
    const NXArchInfo *info;
    uint32_t filetype;
    int num_commands;
    int command_block_size;
    unsigned long command_space;
    mach_o_command *commands;
} *Slice;

static Slice slice_init(FILE *mach_o_file, int offset, bool verbose);
static void  slice_destroy(Slice slice);
static void  swap_data_bytes(Slice slice, mach_o_command *command);
static int   aligned_command_size(Slice slice, int min_size);
static void  update_header(Slice slice);
static void  compute_command_space(Slice slice);
static bool  find_rpath(Slice slice, char *rpath);
static void  remove_command(Slice slice, int index);

typedef struct macho {
    bool verbose;
    bool is_fat;
    FILE *mach_o_file;
    int num_archs;
    struct fat_arch *archs;
    Slice *slices;
} *MachO;

static MachO macho_init(char *mach_o_path, char *mode, bool verbose);
static void macho_destroy(MachO mach_o);
static void show_slice_info(MachO mach_o, int index);

/* actions */
static int print_command(Slice slice, mach_o_command *command, char **args);
static int print_segment(Slice slice, mach_o_command *command, char **args);
static int add_rpath(Slice slice, mach_o_command *command, char **args);
static int remove_rpath(Slice slice, mach_o_command *command, char **args);
static int edit_libpath(Slice slice, mach_o_command *command, char **args);

static void  usage();
extern void  append_data(char *mach_path, char *data_path, char *output_path);

static Slice slice_init(FILE *mach_o_file, int offset, bool verbose)
{
    uint32_t magic;
    struct load_command lc;
    mach_o_command mc;
    struct fat_header fathead;
    Slice slice = calloc(sizeof(struct slice), 1);
    slice->verbose = verbose;
    slice->mach_o_file = mach_o_file;
    slice->offset = offset;
    /*
     * Read the magic number to figure out which type of slice we have.
     */
    fseek(slice->mach_o_file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, slice->mach_o_file);
    fseek(slice->mach_o_file, slice->offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, slice->mach_o_file);
    switch (magic) {
    case MH_MAGIC_64:
	slice->is_64bit = true;
	slice->reverse_bytes = false;
	break;
    case MH_MAGIC:
	slice->is_64bit = false;
	slice->reverse_bytes = false;
	break;
    case OSSwapInt32(MH_MAGIC_64):
	slice->is_64bit = true;
	slice->reverse_bytes = true;
	break;
    case OSSwapInt32(MH_MAGIC):
	slice->is_64bit = false;
	slice->reverse_bytes = true;
	break;
    default:
	printf("The Mach-O magic number %x was not recognized.\n", magic);
	exit(1);
	}
    /*
     * Read the Mach-O header.
     */
    fseek(slice->mach_o_file, slice->offset, SEEK_SET);
    if (slice->is_64bit) {
	struct mach_header_64 *header;
	slice->header_size = sizeof(struct mach_header_64);
	slice->header_data = malloc(slice->header_size);
	header = (struct mach_header_64 *) slice->header_data;
	fread(slice->header_data, slice->header_size, 1, slice->mach_o_file);
	if (slice->reverse_bytes) {
	    swap_mach_header_64(header, 0);
	}
	slice->filetype = header->filetype;
	slice->num_commands = header->ncmds;
	slice->command_block_size = header->sizeofcmds;
	slice->info = NXGetArchInfoFromCpuType(header->cputype, header->cpusubtype);
    } else {
	struct mach_header *header;
	slice->header_size = sizeof(struct mach_header);
	slice->header_data = malloc(slice->header_size);
	header = (struct mach_header *) slice->header_data;
	fread(slice->header_data, slice->header_size, 1, slice->mach_o_file);
	if (slice->reverse_bytes) {
	    swap_mach_header(header, 0);
	}
	slice->filetype = header->filetype;
	slice->num_commands = header->ncmds;
	slice->command_block_size = header->sizeofcmds;
	slice->info = NXGetArchInfoFromCpuType(header->cputype, header->cpusubtype);
    }
    /*
     * Copy all of the load commands into memory.  We may add at most one new
     * command, so we allocate space for one extra.
     */
    slice->commands = (mach_o_command *) calloc(1 + slice->num_commands,
						 sizeof(mach_o_command));
    fseek(slice->mach_o_file, slice->offset + slice->header_size, SEEK_SET);
    for (int i = 0; i < slice->num_commands; i++) {
	long pos = ftell(slice->mach_o_file);
	fread(&lc, sizeof(struct load_command), 1, slice->mach_o_file);
	if (slice->reverse_bytes) {
	    swap_load_command(&lc, 0);
	}
	mc.reversed = false;
	mc.position = pos;
	mc.lc = lc;
	mc.data = malloc(lc.cmdsize);
	fseek(slice->mach_o_file, pos, SEEK_SET);
	fread(mc.data, lc.cmdsize, 1, slice->mach_o_file);
	swap_data_bytes(slice, &mc);
	slice->commands[i] = mc;
    }
    /*
     * Check how much space is available in the file for commands.
     */
    compute_command_space(slice);
    return slice;
}

static void slice_destroy(Slice slice)
{
    for (int i = 0; i < slice->num_commands; i++) {
	mach_o_command *command = slice->commands + i;
	if (command->data) {
	    free(command->data);
	    command->data = NULL;
	}
    }
    if (slice->info) {
	NXFreeArchInfo(slice->info);
    }
    free(slice->commands);
    slice->commands = NULL;
    free(slice->header_data);
    slice->header_data = NULL;
    free(slice);
}

static int aligned_command_size(Slice slice, int min_size)
{
    if (slice->is_64bit) {
	return (min_size + 15) & ~15;
    } else {
	return (min_size + 7) + ~7;
    }
}

static void swap_data_bytes(Slice slice, mach_o_command *command)
{
    /*
     * Don't do anything to commands that we don't change.
     */
    if (!slice->reverse_bytes) {
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

static void update_header(Slice slice)
{
    if (slice->is_64bit) {
	struct mach_header_64 *header = (struct mach_header_64 *)
	    slice->header_data;
	header->ncmds = slice->num_commands;
	header->sizeofcmds = slice->command_block_size;
	fseek(slice->mach_o_file, slice->offset, SEEK_SET);
	if (slice->reverse_bytes) {
	    swap_mach_header_64(header, 0);
	    fwrite(slice->header_data, sizeof(struct mach_header_64), 1,
		   slice->mach_o_file);
	    swap_mach_header_64(header, 0);
	} else {
	    fwrite(slice->header_data, sizeof(struct mach_header_64), 1,
		   slice->mach_o_file);
	}
    } else {
	struct mach_header *header = (struct mach_header *)
	    slice->header_data;
	header->ncmds = slice->num_commands;
	header->sizeofcmds = slice->command_block_size;
	fseek(slice->mach_o_file, slice->offset, SEEK_SET);
	if (slice->reverse_bytes) {
	    swap_mach_header(header, 0);
	    fwrite(slice->header_data, sizeof(struct mach_header), 1,
		   slice->mach_o_file);
	    swap_mach_header(header, 0);
	} else {
	    fwrite(slice->header_data, sizeof(struct mach_header), 1,
		   slice->mach_o_file);
	}
	    
    }
}

static void remove_command(Slice slice, int index)
{
    mach_o_command *command = slice->commands + index;
    mach_o_command empty = {0};
    int command_size = command->lc.cmdsize;
    int tail_size = slice->command_space - command->position - command_size;
    char *tail = malloc(tail_size);
    free(command->data);
    command->data = NULL;
    fseek(slice->mach_o_file, command->position + command_size, SEEK_SET);
    fread(tail, tail_size, 1, slice->mach_o_file);
    fseek(slice->mach_o_file, command->position, SEEK_SET);
    fwrite(tail, tail_size, 1, slice->mach_o_file);
    fwrite(&zero, 1, command_size, slice->mach_o_file);
    free(tail);
    for (int i = index; i < slice->num_commands - 1; i++) {
	slice->commands[i] = slice->commands[i + 1];
	slice->commands[i].position -= command_size;
    }
    slice->num_commands -= 1;
    slice->commands[slice->num_commands] = empty;
    slice->command_block_size -= command_size;
    update_header(slice);
}

static void compute_command_space(Slice slice)
{
    int command_space = -1;
    for (int i = 0; i < slice->num_commands; i++) {
	mach_o_command *command = slice->commands + i;
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
	slice->command_space = command_space;
    } else {
	slice->command_space = 0;
    }
}

static bool find_rpath(Slice slice, char *rpath)
{
    for (int i = 0; i < slice->num_commands; i++) {
	mach_o_command *command = slice->commands + i;
	if (command->lc.cmd == LC_RPATH && command->data) {
	    struct rpath_command *rp = (struct rpath_command *) command->data;
	    char *command_rpath = (char *) rp + rp->path.offset;
	    if (!strcmp(rpath, command_rpath)) {
	    	return true;
	    }
	}
    }
    return false;
}

static int print_command(Slice slice, mach_o_command *command, char **args)
{
    int command_id = command->lc.cmd & ~LC_REQ_DYLD;
    switch (command_id) {
    case LC_SEGMENT:
	{
	    struct segment_command *seg =
		(struct segment_command *)command->data;
	    printf("    LC_SEGMENT %s [%u : %u]\n", seg->segname, seg->fileoff,
		   seg->fileoff + seg->filesize);
	    if (slice->verbose) {
		struct section *section = (struct section *)
		    ((char *)seg + sizeof(struct segment_command));
		if(seg->nsects != 0){
		    for(int i = 0; i < seg->nsects; i++){
			printf("        Section %s [%u : %u ]\n", section->sectname,
			       section->offset, section->offset + section->size);
			section++;
		    }
		} else {
		    printf("        No sections\n");
		}
	    }
	}
	break;
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *seg = (struct segment_command_64 *)
		command->data;
	    printf("    LC_SEGMENT_64 %s [%llu : %llu]\n", seg->segname, seg->fileoff,
		   seg-> fileoff + seg->filesize);
	    if (slice->verbose) {
		struct section_64 *section = (struct section_64 *)
		    ((char *)seg + sizeof(struct segment_command_64));
		if(seg->nsects != 0){
		    for(int i = 0; i < seg->nsects; i++){
			printf("        Section %s [%u : %llu ]\n", section->sectname,
			       section->offset, section->offset + section->size);
			section++;
		    }
		} else {
		    printf("        No sections\n");
		}
	    }
	}
	break;
    case LC_ID_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("    LC_ID_DYLIB: %s\n",
		   (char *)command->data + dl->dylib.name.offset);
	}
	break;
    case LC_LOAD_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("    LC_LOAD_DYLIB: %s\n",
		   (char *) command->data + dl->dylib.name.offset);
	}
	break;
    case LC_UUID:
	{
	    struct uuid_command *uu = (struct uuid_command *)command->data;
	    char uuid[37];
	    uuid[0] = '\0';
	    uuid_unparse(uu->uuid, uuid);
	    printf("    LC_UUID: %s\n", uuid);
	}
	break;
    case LC_SYMTAB:
	{
	    struct symtab_command *tab = (struct symtab_command *)command->data;
	    printf("    LC_SYMTAB: offset is %d, %u symbols, strings in [%d : %d]\n",
		   tab->symoff, tab->nsyms, tab->stroff,
		   tab->stroff + tab->strsize);
	}
	break;
    case LC_RPATH & ~LC_REQ_DYLD:
	{
	    struct rpath_command *rp = (struct rpath_command *)command->data;
	    printf("    LC_RPATH: %s\n", (char *) rp + rp->path.offset);
	}
	break;
    case LC_DYLD_INFO:
	{
	    printf("%s%s\n", "    LC_DYLD_INFO",
		   (command->lc.cmd & LC_REQ_DYLD) != 0 ? "_ONLY" : "");
	}
	break;
    case LC_BUILD_VERSION:
	{
	    struct build_version_command *version =
		(struct build_version_command *)command->data;
	    int min = version->minos;
	    int sdk = version->sdk;
	    printf("    LC_BUILD_VERSION: min = %d.%d.%d, sdk = %d.%d.%d\n",
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
	    printf("    LC_SOURCE_VERSION: %d.%d.%d.%d.%d\n" , parts[4],
		   parts[3], parts[2], parts[1], parts[0]);
	}
	break;
    case LC_VERSION_MIN_MACOSX:
	{
	    struct version_min_command *version =
		(struct version_min_command *)command->data;
	    int min = version->version;
	    int sdk = version->sdk;
	    printf("    LC_VERSION_MIN_MACOSX: min = %d.%d.%d, sdk = %d.%d.%d\n",
		   MAJOR(min), MINOR(min), PATCH(min), MAJOR(sdk), MINOR(sdk),
		   PATCH(sdk));
	}
	break;
    default:
	if (command_id < num_load_commands) {
	    printf("    %s\n", load_command_names[command_id]);
	} else {
	    printf("Invalid command id %d.\n", command_id);
	    exit(1);
	}
	break;
    }
    return 0;
}

static int print_segment(Slice slice, mach_o_command *command, char **args)
{
    if (command->lc.cmd == LC_SEGMENT || command->lc.cmd == LC_SEGMENT_64) {
	print_command(slice, command, args);
    }
    return 0;
}

static int add_rpath(Slice slice, mach_o_command *command, char **args)
{
    char *rpath = args[0];
    mach_o_command *mc = slice->commands + slice->num_commands;
    struct rpath_command *rc;
    int min_size = sizeof(struct rpath_command) + strlen(rpath) + 1;
    int command_size = aligned_command_size(slice, min_size);
    if (command_size + slice->command_block_size > slice->command_space) {
	printf("There is not enough space in the file for another RPATH.\n");
	exit(1);
    }
    if (slice->verbose) {
	printf("Adding rpath %s\n", rpath);
    }
    mc->lc.cmd = LC_RPATH;
    mc->lc.cmdsize = command_size;
    mc->reversed = false;
    mc->position = slice->header_size + slice->command_block_size;
    mc->data = calloc(command_size, 1);
    rc = (struct rpath_command *) mc->data;
    rc->cmd = mc->lc.cmd;
    rc->cmdsize = mc->lc.cmdsize;
    rc->path.offset = sizeof(struct rpath_command);
    strcpy((char *) mc->data + rc->path.offset, rpath);
    slice->num_commands += 1;
    slice->command_block_size += command_size;
    slice->command_space -= command_size;
    fseek(slice->mach_o_file, mc->position, SEEK_SET);
    int count = fwrite((char *) mc->data, 1, command_size, slice->mach_o_file);
    update_header(slice);
    return 1;
}

static int remove_rpath(Slice slice, mach_o_command *command, char **args)
{
    char *rpath = args[0];
    if (command->lc.cmd == LC_RPATH) {
	struct rpath_command *rp = (struct rpath_command *) command->data;
	char *command_path = (char *) rp + rp->path.offset;
	if (!strcmp(rpath, command_path)) {
	    if (slice->verbose) {
		printf("Removed RPATH load command for %s\n", rpath);
	    }
	    remove_command(slice, command - slice->commands);
	}
    }
    return 0;
}

static void change_dylib_path(Slice slice, mach_o_command *command, char *path)
{
    int index = command - slice->commands;
    struct dylib_command *dc = (struct dylib_command *) command->data;
    char *old_path = (char *) dc + dc->dylib.name.offset;
    struct dylib_command *new_command;
    unsigned int old_size = command->lc.cmdsize;
    unsigned int min_size = old_size + strlen(path) - strlen(old_path);
    unsigned int new_size = aligned_command_size(slice, min_size);
    int delta = new_size - old_size;
    char *tail;
    unsigned int tail_size = slice->offset + slice->command_space -
	command->position - old_size;
    if (slice->command_block_size + delta > slice->command_space) {
	printf("There is not enough space in the file to change the id.\n");
	exit(1);
    }
    tail = malloc(tail_size);
    fseek(slice->mach_o_file, command->position + old_size, SEEK_SET);
    fread(tail, tail_size, 1, slice->mach_o_file);
    fseek(slice->mach_o_file, command->position, SEEK_SET);
    command->data = calloc(new_size, 1);
    command->lc.cmdsize = new_size;
    new_command = (struct dylib_command *) command->data;
    *new_command = *dc;
    new_command->cmdsize = new_size;
    strcpy((char *)new_command + new_command->dylib.name.offset, path);
    fwrite(command->data, new_size, 1, slice->mach_o_file);
    int answer = fwrite(tail, tail_size, 1, slice->mach_o_file);
    free(tail);
    for (int i = index; i < slice->num_commands; i++) {
	slice->commands[i].position += delta;
    }
    slice->command_block_size += delta;
    slice->command_space -= delta;
    update_header(slice);
    free(command->data);
    command->data = NULL;
}
	
static int edit_libpath(Slice slice, mach_o_command *command, char **args)
{
    char *newpath = args[0], *oldpath = args[1];
    struct dylib_command *dc = (struct dylib_command *) command->data;
    char *current_libpath = (char *) dc + dc->dylib.name.offset;
    if (command->lc.cmd != LC_LOAD_DYLIB) {
	if (command - slice->commands == slice->num_commands - 1) {
	    printf("No LC_LOAD_DYLIB command matches %s.\n",
		   oldpath == NULL ? basename(newpath) : oldpath);
	}
	return 0;
    }
    if (oldpath == NULL) {
	char libname[strlen(basename(newpath)) + 1];
	char *current_libname = basename(current_libpath);
	strcpy(libname, basename(newpath));
	if (strcmp(libname, current_libname) == 0) {
	    change_dylib_path(slice, command, newpath);
	    return 1;
	}
    } else {
	if (strcmp(oldpath, current_libpath) == 0) {
	    change_dylib_path(slice, command, newpath);
	    return 1;
	}
    }
    return 0;
}

static int set_id(Slice slice, mach_o_command *command, char **args)
{
    char *idpath = args[0];
    if (command->lc.cmd != LC_ID_DYLIB) {
	return 0;
    }
    change_dylib_path(slice, command, idpath);
    return 1;
}

static MachO macho_init(char *mach_o_path, char *mode, bool verbose){
    uint32_t magic;
    struct fat_header fathead;
    MachO mach_o = calloc(sizeof(struct macho), 1);
    struct stat st;

    stat(mach_o_path, &st);
    mach_o->mach_o_file = fopen(mach_o_path, mode);
    if (! mach_o->mach_o_file) {
	printf("Could not open mach-o file %s\n", mach_o_path);
	exit(1);
    }
    mach_o->verbose = verbose;
    fseek(mach_o->mach_o_file, 0, SEEK_SET);
    /*
     * Check the magic number to see if this is a fat binary.
     */
    fread(&magic, sizeof(uint32_t), 1, mach_o->mach_o_file);
    if (magic == FAT_MAGIC || magic == OSSwapInt32(FAT_MAGIC)) {
	mach_o->is_fat = true;
	fseek(mach_o->mach_o_file, 0, SEEK_SET);
	fread(&fathead, sizeof(struct fat_header), 1, mach_o->mach_o_file);
	swap_fat_header(&fathead, 0);
	mach_o->num_archs = fathead.nfat_arch;
	mach_o->archs = calloc(sizeof(struct fat_arch), mach_o->num_archs);
	fread(mach_o->archs, sizeof(struct fat_arch), mach_o->num_archs,
	      mach_o->mach_o_file);
	swap_fat_arch(mach_o->archs, mach_o->num_archs, 0);
    } else {
	struct mach_header header;
	fseek(mach_o->mach_o_file, 0, SEEK_SET);
	fread(&header, sizeof(struct mach_header), 1, mach_o->mach_o_file);
	struct fat_arch arch = {
	    .cputype = header.cputype,
	    .cpusubtype = header.cpusubtype,
	    .offset = 0,
	    .size = st.st_size,
	    .align = 0 
	};
	mach_o->is_fat = false;
	mach_o->num_archs = 1;
	mach_o->archs = calloc(sizeof(struct fat_arch), 1);
	mach_o->archs[0] = arch;
    }
    if (verbose) {
	if (mach_o->is_fat) {
	    printf("The Mach-O file %s is a fat binary with %d architectures.\n",
		   mach_o_path, mach_o->num_archs);
	} else {
	    printf("The Mach-O file %s is a thin binary.\n", mach_o_path);
	}
	printf("The file size is %llu bytes.\n", st.st_size);
    }
    mach_o->slices = (Slice *) calloc(sizeof(Slice), mach_o->num_archs); 
    for (int i = 0; i < mach_o->num_archs; i++) {
	mach_o->slices[i] = slice_init(mach_o->mach_o_file,
	    mach_o->archs[i].offset, mach_o->verbose);
    }
    return mach_o;
}

static void show_slice_info(MachO mach_o, int index) {
    if (index >= mach_o->num_archs) {
	fprintf(stderr, "Index overflow in show_slice_info\n");
	exit(1);
    }
    Slice slice = mach_o->slices[index];
    struct mach_header *header = (struct mach_header *) slice->header_data;
    printf("\nSlice: %d\n", index);
    printf("Filetype: %s\n", filetype_names[header->filetype]);
    printf("Architecture: %s\n", slice->info->name);
    printf("Load Commands:\n");
    if (slice->verbose) {
	printf("Offset: %d\n", slice->offset);
	printf("Space used for load commands: %d bytes (%u load commands)\n",
	       slice->command_block_size, slice->num_commands);
	printf("Space available for load commands: %lu bytes\n\n",
	       slice->command_space);
    }
}

static void macho_destroy(MachO mach_o){
    if (mach_o->slices) {
	for (int i = 0; i < mach_o->num_archs; i++) {
	    slice_destroy(mach_o->slices[i]);
	    mach_o->slices[i] = NULL;
	}
	free(mach_o->slices);
    }
    if (mach_o->archs) {
	free(mach_o->archs);
    }
    fclose(mach_o->mach_o_file);
}

static void usage()
{
    printf("Usage: \n");
    printf("    macher [-v|--verbose] help\n");
    printf("    macher [-v|--verbose] version\n");
    printf("    macher [-v|--verbose] segments <mach-O file>\n");
    printf("    macher [-v|--verbose] commands <mach-O file>\n");
    printf("    macher [-v|--verbose] append <mach-O file> <data file> <output>\n");
    printf("    macher [-v|--verbose] add_rpath <library dir> <Mach-O file path>\n");
    printf("    macher [-v|--verbose] remove_rpath <library dir> <Mach-O file path>\n");
    printf("    macher [-v|--verbose] edit_libpath <new path> <Mach-O file path>\n");
    printf("    macher [-v|--verbose] edit_libpath <old path> <new path> <Mach-O file path>\n");
    printf("    macher [-v|--verbose] set_id <library path> <Mach-O file path>\n");
    exit(1);
}

typedef int (*action_op)(Slice slice, mach_o_command *command, char **arg);

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
    FILE *mach_file;
    static int verbose_flag;
    int option_index = 0;
    char *command;
    mach_o_action action = {0};
    char *mode, *mach_path, *data_path, *output_path;
    char *action_args[2] = {NULL, NULL};
    Slice slice;
    MachO mach_o;

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
    if (action.id == 0) {
	usage();
    }
    switch(action.id) {
    case HELP:
	usage();
	break;
    case VERSION:
	printf("This is version %s of macher.\n", MACHER_VERSION);
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
    case EDIT_LIBPATH:
	if (argc < optind + 2 || argc > optind + 3) {
	    usage();
	}
	if (argc == optind + 3) {
	    action_args[1] = argv[optind++];
	}
	action_args[0] = argv[optind++];
	mode = "r+";
	mach_path = argv[optind];
	break;
    case ADD_RPATH:
    case REMOVE_RPATH:
    case SET_ID:
	if (argc != optind + 2) {
	    usage();
	}
	mode = "r+";
	action_args[0] = argv[optind++];
	mach_path = argv[optind];
	break;
    default:
	if (argc != optind + 1) {
	    usage();
	}
	mode = "r";
	mach_path = argv[optind];
	break;
    }
    mach_o = macho_init(mach_path, mode, verbose_flag);
    for (int i = 0; i < mach_o->num_archs; i++) {
	slice = mach_o->slices[i];
	if (action.id == COMMANDS || mach_o->verbose) {
	    show_slice_info(mach_o, i);
	}
	if ((action.id == ADD_RPATH) && find_rpath(slice, action_args[0])) {
	    printf("An RPATH load command for %s already exists.\n", action_args[0]);
	    continue;
	}
	if ((action.id == REMOVE_RPATH) && !find_rpath(slice, action_args[0])) {
	    printf("No RPATH load command for %s exists.\n", action_args[0]);
	    continue;
	}
	if ((action.id == SET_ID) && (slice->filetype != MH_DYLIB)) {
	    printf("The dylib id can only be set for a dylib file.\n");
	    continue;
	}
	if (action.op) {
	    for (int i = 0; i < slice->num_commands; i++) {
		int count = slice->num_commands;
		if (action.op(slice, slice->commands + i, action_args)) {
		    break;
		}
		if (action.id == REMOVE_RPATH &&
		    count > slice->num_commands) {
		    i--;
		}
	    }
	}
    }
    macho_destroy(mach_o);
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
