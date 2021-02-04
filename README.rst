Macher
=====

Macher is a command line tool for inspecting and modifying Mach-O binary files as produced
by Apple's clang C compiler.

Macher provides some functions which are similar to those provided by Apple's install_name_tool
and otool programs, as well as some functions which are not available with those programs.

When running macher in a shell the general format is:

$ macher [-options] <command> <command args>...

The only option is -v or, in long form --verbose, which adds additional output compared
to what is available without this option.

Here is a list of the available formats:

segments
     $ macher [-options] segments <Mach-O file path>

     Prints information about each segment in the Mach-O file.  In verbose mode, the
     sections within each segment are listed, along with byte ranges showing the
     location of the segment within the file.

commands
    $ macher [-options] commands <Mach-O file path>

    Prints information about each load command in the Mach-O file.  This includes the
    load commands which define segments.  The verbose mode provides additional
    details about the command.  This is similar to otool -l but generates output which
    is more readable and amenable to being parsed by a script.

append
    $ macher [-options] append <data file path> <Mach-O file path>

    This command appends arbitrary data to the end of the Mach-O file and alters both the
    __LINKEDIT segment load command and the __SYMTAB load command , making the
    extra data become part of the string data block which appears at the end of the __LINKEDIT
   segment.  The __LINKEDIT segment is the last segment in the file and is required to extend to
   the end of the  file.

   The main purpose of this command is to make it possible to produce a Zip self-extracting
   archive by appending a Zip file to the end of a Mach-O binary file without producing an
   invalid Mach-O binary file.  Simply appending the Zip file corrupts Mach-O structure by
   making the __LINKEDIT segment fail to extend to the end of the file.

