Macher
=====

Macher is a command line tool for inspecting and modifying Mach-O binary files
as produced by Apple's clang C compiler.

Macher provides some functions which are similar to those provided by Apple's
install_name_tool and otool programs, as well as some functions which are not
available with those programs.

When running macher in a shell the general format is:

$ macher [-options] <command> <command args>...

The only option is -v or --verbose, which adds additional output compared to
what is available without this option.

Here is a list of the available commands:

segments
     $ macher [-options] segments <Mach-O file path>

     Prints information about each segment in the Mach-O file.  In verbose mode,
     the sections within each segment are listed, along with byte ranges showing
     the location of the segment within the file.

commands
    $ macher [-options] commands <Mach-O file path>

    Prints information about each load command in the Mach-O file.  This
    includes the load commands which define segments.  The verbose mode provides
    additional details about the command.  This is similar to otool -l but
    generates output which is more readable and amenable to being parsed by a
    script.

append
    $ macher [-options] append <data file path> <Mach-O file path>

    Appends arbitrary data to the end of the Mach-O file and alters both the
    load command for the __LINKEDIT segment and the LC_SYMTAB load command,
    making the extra data become part of the string data block which appears at
    the end of the __LINKEDIT segment.  The __LINKEDIT segment is the last
    segment in the file and is required to extend to the end of the file.

    The main purpose of this command is to make it possible to produce a Zip
    self-extracting archive, by appending a Zip file to the end of a Mach-O
    binary file, without creating an invalid Mach-O binary file.  Simply
    appending the Zip file without modifying the load commands corrupts the
    Mach-O structure by causing the __LINKEDIT segment not to extend to the
    end of the file as required.

    After appending a Zip file, the :code:`zip -A` command should be used to
    adjust the offset tables within the Zip data.

add_rpath
    $ macher [-options] add_rpath <library search path> <Mach-O file path>

    Adds an LC_RPATH load command with the specified search path.  This is
    equivalent to :code"`install_name_tool -add_rpath` except that it will not
    add the load command if there already exists an LC_RPATH load command with
    the same path.

    If there is a LC_DYLIB command containing the substring @rpath then the
    loader will search for the library in all paths obtained by replacing
    @rpath by one of the paths given in LC_RPATH load commands.

remove_rpath
    $ macher [-options] remove_rpath <library search path> <Mach-O file path>

    Removes all LC_RPATH load commands specifying the given search path.

edit_libpath
    $ macher [-options] edit_libpath <dylib path> <Mach-O file path>

    Searches for an LC_DYLIB load command for which the library file name is the
    same as the file name for the specified path.  If one is found, the dylib
    path in the command is replaced by the specified path.

    This is similar to :code:`install_name_tool -change` except that it does not
    require that you provide the existing path to be replaced.  It uses the file
    name of the dylib to decide whether to do the replacement.
