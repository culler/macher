#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>
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
    int num_commands;
    unsigned long command_space;
    mach_o_command *commands;
} mach_o_obj;

static void swap_data_bytes(mach_o_obj *mach_o, mach_o_command *command);
static void update_header(mach_o_obj *mach_o, int num_cmds, int size_change);
static void print_command(mach_o_obj *mach_o, mach_o_command *command, char *arg);
static void print_segment(mach_o_obj *mach_o, mach_o_command *command, char *arg);
static void compute_command_space(mach_o_obj *mach_o);
static void remove_command(mach_o_obj *mach_o, int index);
static void init_mach_o(mach_o_obj *mach_o, char *path, char *mode);
static void destroy_mach_o(mach_o_obj *mach_o);
static void usage();


static void init_mach_o(mach_o_obj *mach_o, char *path, char *mode) {
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
    if (mach_o->verbose) {
	struct stat st;
	stat(mach_o->path, &st);
	printf("Mach-O magic number is 0x%x.\n", magic);
	printf("Mach-O file size is %llu.\n", st.st_size);
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
	mach_o->num_commands = header->ncmds;
	if (mach_o->verbose) {
	    printf("There are %u bytes being used to store %u load commands.\n",
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
	mach_o->num_commands = header->ncmds;
	if (mach_o->verbose) {
	    printf("There are %u bytes being used to store %u load commands.\n",
		   header->sizeofcmds, header->ncmds);
	}
    }
    /*
     * Copy all of the load commands into memory.
     */
    mach_o->commands = (mach_o_command *) malloc(
		            sizeof(mach_o_command) * mach_o->num_commands);
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

static void destroy_mach_o(mach_o_obj *mach_o) {
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

static void update_header(mach_o_obj *mach_o, int ncmds, int size_change) {
    if (mach_o->is_64bit) {
	struct mach_header_64 *header = (struct mach_header_64 *)
	    mach_o->header_data;
	header->ncmds = ncmds;
	header->sizeofcmds += size_change;
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
	header->ncmds = ncmds;
	header->sizeofcmds += size_change;
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

static void print_command(mach_o_obj *mach_o, mach_o_command *command, char *arg) {
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
	printf("%s\n", load_command_names[command_id]);
	break;
    }
}

static void remove_command(mach_o_obj *mach_o, int index){
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
    mach_o->command_space += command_size;
    update_header(mach_o, mach_o->num_commands, -command_size);
}

static void print_segment(mach_o_obj *mach_o, mach_o_command *command, char *arg) {
    if (command->lc.cmd == LC_SEGMENT || command->lc.cmd == LC_SEGMENT_64) {
	print_command(mach_o, command, arg);
    }
}

static void compute_command_space(mach_o_obj *mach_o) {
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
	    printf("There are %lu bytes available for storing load commands.\n\n",
		   mach_o->command_space);
	}
    } else {
	mach_o->command_space = 0;
    }
}

void append_data(mach_o_obj *mach_o, mach_o_command *command, char *data_path) {
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
}

static void usage() {
    printf("Usage: \n");
    printf("    mach_o [-v] segments <mach-O file>\n");
    printf("    mach_o [-v] commands <mach-O file>\n");
    printf("    mach_o [-v] append <datafile> <mach-O file>\n");
    exit(1);
}

typedef void (*action_op)(mach_o_obj *mach_o, mach_o_command *command, char *arg);

typedef enum {HELP=1, SEGMENTS, COMMANDS, APPEND} action_id;

typedef struct {
    action_id id;
    char *name;
    action_op op;
} mach_o_action;

static mach_o_action actions[] = {
    {.id = HELP, .name = "help", .op = NULL},
    {.id = COMMANDS, .name = "commands", .op = print_command},
    {.id = SEGMENTS, .name = "segments", .op = print_segment},
    {.id = APPEND, .name = "append", .op = append_data},
    {0}
};

int main(int argc, char **argv)
{
    mach_o_obj mach_o = {0};
    char *mach_o_path;
    static int verbose_flag;
    int option_index = 0;
    char *command;
    mach_o_action action = {0};
    char *mode, *mach_o_file, *action_arg;

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
    case APPEND:
	if (argc != optind + 2) {
	    usage();
	}
	mode = "r+";
	action_arg = argv[optind++];
	mach_o_file = argv[optind];
	break;
    default:
	if (argc != optind + 1) {
	    usage();
	}
	mode = "r";
	mach_o_file = argv[optind];
	action_arg = NULL;
	break;
    }
    init_mach_o(&mach_o, mach_o_file, mode);
    if (action.op) {
	for (int i = 0; i < mach_o.num_commands; i++) {
	    action.op(&mach_o, mach_o.commands + i, action_arg);
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
