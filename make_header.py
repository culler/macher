import os
import re
get_command = re.compile('#define\s(LC_[A-Z_]*).*(0x[0-9a-fA-F]*)')
get_filetype = re.compile('#define\s(MH_[A-Z_]*).*(0x[0-9a-fA-F]*)')
sdk = '/Library/Developer/CommandLineTools/SDKs/MacOSX12.0.sdk'
print('char* load_command_names[] = {')
count = 0
with open(os.path.join(sdk, 'usr', 'include', 'mach-o', 'loader.h')) as input_file:
    for line in input_file.readlines():
        m = get_command.match(line)
        if m:
            groups = m.groups()
            groups = [groups[1].lower(), groups[0]]
            header_line = '/*{0}*/  "{1}",'.format(*groups)
            # 0x22 is the only load command which has a REQ_DYLD variant.
            if line.find("LC_REQ_DYLD)") >= 0 and groups[0] == '0x22':
                continue
            print(header_line)
            count += 1;
print('};')
print('int num_load_commands = 0x%x;'%count)

print('char* filetype_names[] = {')
print('/*0x0*/  "Unknown",')
with open(os.path.join(sdk, 'usr', 'include', 'mach-o', 'loader.h')) as input_file:
    started = False
    for line in input_file.readlines():
        if line.find('for the filetype field') > 0:
            started = True
        if not started:
            continue
        m = get_filetype.match(line)
        if m:
            groups = m.groups()
            print('/*{0}*/  "{1}",'.format(groups[1].lower(), groups[0]))
        elif started and line.startswith('/*'):
            break
print('};')

