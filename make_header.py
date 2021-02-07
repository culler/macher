import os
import re
get_command = re.compile('#define\s(LC_[A-Z_]*).*(0x[0-9a-fA-F]*)')
sdk = '/Library/Developer/CommandLineTools/SDKs/MacOSX11.1.sdk'
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


