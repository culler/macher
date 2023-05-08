Macher
======

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

help
    $ macher help

    Prints usage information.

version
    $ macher version

    Prints the version number.

segments
    $ macher [-options] segments <Mach-O file path>

    Prints information about each segment in the Mach-O file.  In verbose mode,
    the sections within each segment are listed.

commands
    $ macher [-options] commands <Mach-O file path>

    Prints information about each load command in the Mach-O file.  This
    includes the load commands which define segments.  The verbose mode provides
    additional details about the commands.  This is similar to otool -l but
    generates output which is more readable and amenable to being parsed by a
    script.

append
    $ macher [-options] append <Mach-O file path> <data file path> <output path>

    Creates a fat binary by adding a new slice containing arbitrary data at the
    end of a Mach-O file.  The new slice is tagged for the "any" architecture
    and is guaranteed to be the last slice in the fat binary.

    The main purpose of this command is to make it possible to produce a Zip
    self-extracting archive without creating an invalid Mach-O binary file.  Simply
    appending a Zip file to the end of a thin or fat binary corrupts the Mach-O
    structure by causing the __LINKEDIT segment of the last slice not to extend
    to the end of the file as required.

    After appending a Zip file, the :code:`zip -A` command should be used to
    adjust the offset tables within the Zip data.  After doing this, the files
    in the zip archive can be exracted by calling :code:`unzip` as if the fat
    binary were an ordinary zip archive.

add_rpath
    $ macher [-options] add_rpath <library search path> <Mach-O file path>

    Adds an LC_RPATH load command with the specified search path.  This is
    equivalent to :code:`install_name_tool -add_rpath` except that it will not
    add the load command if there already exists an LC_RPATH load command with
    the same path.

    If there is a LC_DYLIB command containing the substring @rpath then the
    loader will search for the library in all paths obtained by replacing
    @rpath by one of the paths given in LC_RPATH load commands.

remove_rpath
    $ macher [-options] remove_rpath <library search path> <Mach-O file path>

    Removes all LC_RPATH load commands specifying the given search path.

clear_rpaths
    $ macher [-options] clear_rpaths <Mach-O file path>

    Removes all LC_RPATH load commands.

remove_signature
    $ macher [-options] remove_signature <Mach-O file path>

    Removes all LC_CODE_SIGNATURE load commands.

edit_libpath
    $ macher [-options] edit_libpath <old path> <new path> <Mach-O file path>
    $ macher [-options] edit_libpath <new path> <Mach-O file path>

    With three arguments,searches for an LC_DYLIB load command for which the
    dylib path is the specified old path. If one is found, the dylib path in the
    command is replaced by the new path.  This is equivalent to
    :code:`install_name_tool -change`.

    With two arguments this command is similar to :code:`install_name_tool
    -change` but it does not require that you provide the exact old dylib path.
    It uses the file name of the old path to decide whether to do the
    replacement.

set_id
    $ macher [-options] set_id <dylib id> <Mach-O file path>

    Sets the path in the LC_ID_DYLIB load command to the specified path. The
    LC_ID_DYLIB load command exists only for dylib files.  When another
    executable is linked with the dylib, the linker copies the id into an
    LC_DYLIB command for the executable.
