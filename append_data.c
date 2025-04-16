#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>

/*
 * This module implements the function append_data which appends arbitrary data to
 * a Mach-O binary file as a fat slice.  The inputs are paths to a Mach-O file,
 * a data file, and a new file which is a fat binary containing all of the slices
 * of the Mach-O binary plus one additional slice at the end which contains the
 * data.  The architecture of the new slice is "little", which corresponds to the
 * cpu type CPU_TYPE_ANY.  It uses 1-byte alignment.
 *
 * The intended purpose of this operation is to create a Zip self-extracting archive
 * which is also a valid Mach-O binary file.  A Zip self-extracting archive is
 * required to contain the zip file at the end, but can have an arbitrary
 * executable file prepended to it.  The unzip command will ignore the prepended
 * binary file and simply unpack the files in the appended zip archive.  But the
 * file appears to the operating system as an executable.
 *
 * For this to work correctly, the Mach-O binary must include the host architecture,
 * so the OS will not attempt to run the zip archive as an executable.  Also, after
 * appending the Zip archive, the command zip -A should be used to adjust the file
 * offsets within the archive to account for the prepended binary. 
 *
 * We have to deal with two cases, depending on whether the Mach-O binary is thin.
 * Care must be taken to ensure that each slice has a page-aligned offset.  While
 * the page-alignment requirement seems to be satisfied with offsets that are
 * multiples of 4K, Apple seems to use multiples of 16K.  So we also use 16K. 
 */

static char zero = 0;

void append_data(
    char *mach_path,
    char *data_path,
    char *output_path)
{
    struct mach_header header = {0};
    struct mach_header_64 header_64 = {0};
    struct fat_header fathead = {0};
    struct fat_arch *archs;
    struct stat st;
    char buffer[512];
    FILE *data, *mach, *output;
    int fathead_size, fathead_padding, mach_size, data_size, data_offset;
    uint32_t magic, cputype, cpusubtype;
    bool isfat = false;

    mach = fopen(mach_path, "r");
    if (! mach) {
	printf("Could not open the Mach-O file %s: %s\n", mach_path,
	       strerror(errno));
	exit(1);
    }
    stat(mach_path, &st);
    mach_size = st.st_size;
    data = fopen(data_path, "r");
    if (! data) {
	printf("Could not open the data file %s: %s\n", data_path,
	       strerror(errno));
	exit(1);
    }
    stat(data_path, &st);
    data_size = st.st_size;
    /*
     * Read the magic number to figure out which type of Mach-O file we have.
     */
    fread(&magic, sizeof(uint32_t), 1, mach);
    fseek(mach, 0, SEEK_SET);
    switch (magic) {
    case FAT_MAGIC:
    case OSSwapInt32(FAT_MAGIC):
	isfat = true;
	fread(&fathead, sizeof(struct fat_header), 1, mach);
	swap_fat_header(&fathead, 0);  /* Convert to native endianness. */
	break;
    case MH_MAGIC_64:
    case OSSwapInt32(MH_MAGIC_64):
	fseek(mach, 0, SEEK_SET);
	fread(&header_64, sizeof(struct mach_header_64), 1, mach);
	cputype = header_64.cputype;
	cpusubtype = header_64.cpusubtype;
    case MH_MAGIC:
    case OSSwapInt32(MH_MAGIC):
	fseek(mach, 0, SEEK_SET);
	fread(&header, sizeof(struct mach_header), 1, mach);
	cputype = header.cputype;
	cpusubtype = header.cpusubtype;
    break;
    default:
	printf("error: %s is not a mach-O file.\n", mach_path);
	exit(1);
    }
    /*
     * Allocate and fill in fat_arch structures.  If the Mach-O file is not fat
     * we use 2^14 byte alignment for its slice, since that is what Apple
     * appears to do.
     */
    if (!isfat) {
        /* Our mach-O file is thin, so it contains just one mach header followed by
         * data.  We need to add a fat header followed by an array of two fat_arch
         * structs and then pad with zeros to a size which is a multiple of 16K.
         * We may then add the existing mach header and its data. That must also
         * be padded so that the data slice added at the end has an offset which
         * is a multiple of 16K.
         */
	fathead.magic = FAT_MAGIC;
	fathead.nfat_arch = 2;
	archs = (struct fat_arch *) calloc(fathead.nfat_arch, sizeof(struct fat_arch));
	fathead_size = sizeof(fathead) + fathead.nfat_arch * sizeof(struct fat_arch);
	fathead_padding = ((fathead_size + 0x3fff) & ~0x3fff) - fathead_size;
	data_offset = ((fathead_size + fathead_padding + mach_size + 0x3fff) & ~0x3fff);
	struct fat_arch arch = {
	    .cputype = cputype,
	    .cpusubtype = cpusubtype,
	    .offset = fathead_size + fathead_padding,
	    .size = mach_size,
	    .align = 14
	};
	archs[0] = arch;
	/*
	 * Seek to the start of the mach header, which is the beginning in this
	 * case.
	 */
	fseek(mach, 0, SEEK_SET); 
    } else {
	/*
	 * Our Mach-O file is already fat.  We need to modify its fat header and
         * add one fat_arch struct to the array.  The existing padding for the
         * header must be adjusted to account for the new fat_arch.  We can then
         * append the existing mach blocks, but padding must be added after those
         * to ensure that the offset of the data slice at the end will be a multiple
         * of 4K. 
	 */
	fseek(mach, 0, SEEK_SET);
	fread(&fathead, sizeof(struct fat_header), 1, mach);
	/*
	 * Convert the fat header to the host's endianness.
	 */
	swap_fat_header(&fathead, 0);
	fathead.nfat_arch++;
	archs = calloc(fathead.nfat_arch + 1, sizeof(struct fat_arch));
	fread(archs, sizeof(struct fat_arch), fathead.nfat_arch - 1, mach);
	/*
	 * Convert the fat_arch structures to the host's endianness.
	 */
	swap_fat_arch(archs, fathead.nfat_arch - 1, 0);
	fathead_size = sizeof(fathead) + fathead.nfat_arch*sizeof(struct fat_arch);
	fathead_padding = archs[0].offset - fathead_size;
        /*
         * If we are very unlucky, adding the new fat_arch to the array may cause
         * the fat header to expand beyond its current padded size.
         */ 
	if (fathead_padding < 0) {
	    fathead_padding += 0x4000;
	    swap_fat_arch(archs, fathead.nfat_arch - 1, 0);
	    for(int i = 0; i < fathead.nfat_arch - 1; i++) {
		archs[i].offset += 0x4000;
	    }
	    swap_fat_arch(archs, fathead.nfat_arch - 1, 0);
	}
	/*
	 * Seek to the start of the first mach header.
	 */
	fseek(mach, archs[0].offset, SEEK_SET);
	data_offset = fathead_size + fathead_padding + mach_size - ftell(mach);
    }
    /*
     * Fill in ia fat_arch for the new data slice.
     */
    struct fat_arch data_arch = {
	.cputype = CPU_TYPE_ANY,
	.cpusubtype = CPU_SUBTYPE_ANY,
	.offset = data_offset,
	.size = data_size,
	.align = 0
    };
    archs[fathead.nfat_arch - 1] = data_arch;
    /*
     * Copy the fat header and padding into the output file.  Apple says
     * that the fat_header and fat_arch structures must always be serialized
     * in bigendian order.
     */
    int num_archs = fathead.nfat_arch;
    output = fopen(output_path, "w");
    if (!output) {
	printf("Could not open output file %s: %s\n", output_path,
	       strerror(errno));
	exit(1);
    }
    swap_fat_arch(archs, num_archs, NX_BigEndian);
    swap_fat_header(&fathead, NX_BigEndian);
    fwrite(&fathead, sizeof(struct fat_header), 1, output);
    fwrite(archs, sizeof(struct fat_arch), num_archs, output);
    fwrite(&zero, 1, fathead_padding, output);
    
    /*
     * Copy the Mach-O file.  Note: we left the file position at the start of
     * the first mach header.
     */
    while (!feof(mach)) {
	int count;
	count = fread(buffer, 1, 512, mach);
	fwrite(buffer, count, 1, output);
    }

    /*
     * Add padding to make sure that the data slice is aligned correctly.
     */
    fpos_t pos;
    fgetpos(output, &pos);
    if (pos % 0x4000) {
	if (data_offset < pos) {
	    fprintf(stderr, "Error computing offset to data slice. Aborting!\n");
	    printf("data_offset: %x; pos: %llx\n", data_offset, pos);
	    exit(-1);
	}
	fwrite(&zero, 1, data_offset - pos, output);
    }
    /*
     * Construct a Mach header for the data slice and write it to the output.
     * We construct the header in the host's endianness.
     */
    struct mach_header datahead = {
        .magic = MH_MAGIC,
	.cputype = CPU_TYPE_ANY,
	.cpusubtype = CPU_SUBTYPE_ANY,
        .filetype = MH_OBJECT,
        .ncmds = 0,
        .sizeofcmds = 0,
        .flags = 0,
    };
    fwrite(&datahead, sizeof(struct mach_header), 1, output);
    while (!feof(data)) {
	int count;
	count = fread(buffer, 1, 512, data);
	fwrite(buffer, count, 1, output);
    }
    fclose(data);
    fclose(output);
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 79
 * coding: utf-8
 * End:
 */

