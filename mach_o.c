#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/fat.h>
#include <mach/mach.h>
#include "mach_o.h"
#define MAJOR(x) ((x >> 16) & 0xff)
#define MINOR(x) ((x >> 8) & 0xff)
#define PATCH(x) (x & 0xff)

typedef struct {
    int position;
    struct load_command lc;
    void *data;
} mach_o_command;

typedef struct {
    bool verbose;
    bool reverse_bytes;
    bool is_64bit;
    char *path;
    FILE *file;
    int header_size;
    int num_commands;
    mach_o_command *commands;
    char *data_path;
} mach_o_obj;

typedef struct mach_o_action_t mach_o_action;

static void swap_data_bytes(mach_o_obj *mach_o, mach_o_command *command) {
    /*
     * Don't do anything to commands that we don't change.
     */
    if (!mach_o->reverse_bytes) {
	return;
    }
    switch (command->lc.cmd) {
    case LC_SEGMENT:
	{
	    struct segment_command *sg = (struct segment_command *) command->data;
	    swap_segment_command(sg, 0);
	    break;
	}
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *sg = (struct segment_command_64 *) command->data;
	    swap_segment_command_64(sg, 0);
	    break;
	}
    case LC_SYMTAB:
	{
	    struct symtab_command *st = (struct symtab_command *) command->data;
	    swap_symtab_command(st, 0);
	    break;
	}
    }
}

static void print_command(mach_o_obj *mach_o, mach_o_command *command) {
    switch (command->lc.cmd & ~LC_REQ_DYLD) {
    case LC_SEGMENT:
	{
	    struct segment_command *seg =
		(struct segment_command *)command->data;
	    printf("LC_SEGMENT: %s [%u : %u]\n", seg->segname, seg->fileoff,
		   seg->fileoff + seg->filesize);
	    break;
	}
    case LC_SEGMENT_64:
	{
	    struct segment_command_64 *seg =
		(struct segment_command_64 *)command->data;
	    printf("LC_SEGMENT_64: %s [%llu : %llu]\n", seg->segname, seg->fileoff,
		   seg-> fileoff + seg->filesize);
	    break;
	}
    case LC_ID_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("LC_ID_DYLIB: %s\n",
		   (char *)command->data + dl->dylib.name.offset);
	    break;
	}
    case LC_LOAD_DYLIB:
	{
	    struct dylib_command *dl = (struct dylib_command *)command->data;
	    printf("LC_LOAD_DYLIB: %s\n",
		   (char *) command->data + dl->dylib.name.offset);
	    break;
	}
    case LC_UUID:
	{
	    struct uuid_command *uu = (struct uuid_command *)command->data;
	    char uuid[37];
	    uuid[0] = '\0';
	    uuid_unparse(uu->uuid, uuid);
	    printf("LC_UUID: %s\n", uuid);
	    break;
	}
    case LC_SYMTAB:
	{
	    struct symtab_command *tab = (struct symtab_command *)command->data;
	    printf("LC_SYMTAB: offset: %d, %u symbols, strings in [%d : %d]\n",
		   tab->symoff, tab->nsyms, tab->stroff,
		   tab->stroff + tab->strsize);
	    break;
	}
    case LC_RPATH:
	{
	    struct rpath_command *rp = (struct rpath_command *)command->data;
	    printf("LC_RPATH: %s\n", (char *) command->data + rp->path.offset);
	    break;
	}
    case LC_DYLD_INFO:
	{
	    printf("%s%s\n", "LC_DYLD_INFO",
		   (command->lc.cmd & LC_REQ_DYLD) != 0 ? "_ONLY" : "");
	    break;
	}
    case LC_BUILD_VERSION:
	{
	    struct build_version_command *version =
		(struct build_version_command *)command->data;
	    int min = version->minos;
	    int sdk = version->sdk;
	    printf("LC_BUILD_VERSION: min = %d.%d.%d, sdk = %d.%d.%d\n",
		   MAJOR(min), MINOR(min), PATCH(min), MAJOR(sdk), MINOR(sdk),
		   PATCH(sdk));
	    break;
	}
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
	    break;
	}
    case LC_VERSION_MIN_MACOSX:
	{
	    struct version_min_command *version =
		(struct version_min_command *)command->data;
	    int min = version->version;
	    int sdk = version->sdk;
	    printf("LC_VERSION_MIN_MACOSX: min = %d.%d.%d, sdk = %d.%d.%d\n",
		   MAJOR(min), MINOR(min), PATCH(min), MAJOR(sdk), MINOR(sdk),
		   PATCH(sdk));
	    break;
	}
    default:
	printf("%s\n", load_command_names[command->lc.cmd & ~LC_REQ_DYLD]);
    }
}

static void print_segment(mach_o_obj *mach_o, mach_o_command *command) {
    if (command->lc.cmd == LC_SEGMENT || command->lc.cmd == LC_SEGMENT_64) {
	print_command(mach_o, command);
    }
}

static void init_mach_o(mach_o_obj *mach_o, mach_o_action *action) {
    uint32_t magic;
    struct load_command lc;
    mach_o_command mc;
    struct stat st;
    FILE *mach_o_file = fopen(mach_o->path, "r");
     
    if (! mach_o_file) {
	printf("Could not open mach-o file %s\n", mach_o->path);
	exit(1);
    }
    stat(mach_o->path, &st);
    fseek(mach_o_file, 0, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, mach_o_file);
    if (mach_o->verbose) {
	printf("Mach-O magic number is 0x%x.\n", magic);
	printf("Mach-O file has size %llu.\n", st.st_size);
    }
    switch (magic) {
    case FAT_MAGIC:
    case OSSwapInt32(FAT_MAGIC):
	printf("Fat binaries are not supported.\n"
	       "Use lipo to split the file into single-architecture binaries.\n");
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
    fseek(mach_o_file, 0, SEEK_SET);
    if (mach_o->is_64bit) {
	struct mach_header_64 header;
	mach_o->header_size = sizeof(struct mach_header_64);
	fread(&header, mach_o->header_size, 1, mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_mach_header_64(&header, 0);
	}
	mach_o->num_commands = header.ncmds;
    } else {
	struct mach_header header;
	mach_o->header_size = sizeof(struct mach_header);
	fread(&header, mach_o->header_size, 1, mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_mach_header(&header, 0);
	}
	mach_o->num_commands = header.ncmds;
    }
    mach_o->commands = (mach_o_command *) malloc(
		            sizeof(mach_o_command) * mach_o->num_commands);
    fseek(mach_o_file, mach_o->header_size, SEEK_SET);
    for (int i = 0; i < mach_o->num_commands; i++) {
	long pos = ftell(mach_o_file);
	fread(&lc, sizeof(struct load_command), 1, mach_o_file);
	if (mach_o->reverse_bytes) {
	    swap_load_command(&lc, 0);
	}
	mc.position = pos;
	mc.lc = lc;
	mc.data = malloc(lc.cmdsize);
	fseek(mach_o_file, pos, SEEK_SET);
	fread(mc.data, lc.cmdsize, 1, mach_o_file);
	mach_o->commands[i] = mc;
    }
    fclose(mach_o_file);
}

static void usage() {
    printf("Usage: \n");
    printf("    mach_o_edit append datafile binaryfile\n");
    printf("    mach_o_edit segments\n");
    printf("    mach_o_edit commands\n");
    exit(1);
}

typedef void (*action_op)(mach_o_obj *mach_o, mach_o_command *command);

typedef enum {COMMANDS=1, SEGMENTS, APPEND} action_id;

struct mach_o_action_t {
    action_id id;
    char *name;
    action_op op;
};

static mach_o_action actions[] = {
    {.id = COMMANDS, .name = "commands", .op = print_command},
    {.id = SEGMENTS, .name = "segments", .op = print_segment},
    {.id = APPEND, .name = "append", .op = NULL},
    {0}
};

int main(int argc, char **argv)
{
    mach_o_obj mach_o = {0};
    char *mach_o_path, *data_path;
    static int verbose_flag;
    struct stat st;
    int option_index = 0;
    char *command;
    mach_o_action action = {0};

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
    if (action.id == 0) {
	usage();
    }
    if (action.id == APPEND) {
	if (optind >= argc) {
	    usage();
	}
	data_path = argv[optind++];
	if (stat(data_path, &st)) {
	    printf("Could not find data file.\n");
	    exit(1);
	}
    }
    mach_o.path = argv[optind];
    init_mach_o(&mach_o, &action);
    for (int i = 0; i < mach_o.num_commands; i++) {
	mach_o_command *command = mach_o.commands + i;
	if (action.op) {
	    action.op(&mach_o, command);
	}
    }
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 79
 * coding: utf-8
 * End:
 */
