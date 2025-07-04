import os   # for join
import struct

mod_fileroot = os.path.join(os.environ.get('LOCALAPPDATA'), 'Packages\\Microsoft.MSEsper_8wekyb3d8bbwe\\RoamingState\\mods')

charmap = {
    '0': 0x01, '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05,
    '5': 0x06, '6': 0x07, '7': 0x08, '8': 0x09, '9': 0x0a,
    'a': 0x0b, 'b': 0x0c, 'c': 0x0d, 'd': 0x0e, 'e': 0x0f,
    'f': 0x10, 'g': 0x11, 'h': 0x12, 'i': 0x13, 'j': 0x14,
    'k': 0x15, 'l': 0x16, 'm': 0x17, 'n': 0x18, 'o': 0x19,
    'p': 0x1a, 'q': 0x1b, 'r': 0x1c, 's': 0x1d, 't': 0x1e,
    'u': 0x1f, 'v': 0x20, 'w': 0x21, 'x': 0x22, 'y': 0x23,
    'z': 0x24, '-': 0x25, '_': 0x25
}

reverse_charmap = {
    0x01: '0', 0x02: '1', 0x03: '2', 0x04: '3', 0x05: '4',
    0x06: '5', 0x07: '6', 0x08: '7', 0x09: '8', 0x0a: '9',
    0x0b: 'a', 0x0c: 'b', 0x0d: 'c', 0x0e: 'd', 0x0f: 'e',
    0x10: 'f', 0x11: 'g', 0x12: 'h', 0x13: 'i', 0x14: 'j',
    0x15: 'k', 0x16: 'l', 0x17: 'm', 0x18: 'n', 0x19: 'o',
    0x1a: 'p', 0x1b: 'q', 0x1c: 'r', 0x1d: 's', 0x1e: 't',
    0x1f: 'u', 0x20: 'v', 0x21: 'w', 0x22: 'x', 0x23: 'y',
    0x24: 'z', 0x25: '-'
}


def convert_int(n):
    """Convert an integer to a string using the character map."""
    r = ''
    while n:
        if n % 40 in reverse_charmap:
            r += reverse_charmap[n % 40]
        n //= 40
    return r[::-1]


def convert_str(s):
    """Convert a string into an integer through the character map."""
    if len(s) > 12:
        return -1
    a = 0
    b = 0
    i = 0
    for c in s:
        real_c = c.lower()
        if real_c in charmap:
            if i < 6:
                a *= 40
                a += charmap[real_c]
            else:
                b *= 40
                b += charmap[real_c]
        i += 1
    return a, b

def to_offset(block):
    return block * 4 + 0x20

def to_block(offset):
    return (offset - 0x20) // 4


class SSBFunc:
    def __init__(self, name="", bounds=(0, 0), numparams=-1, returns=False):
        self.name = name
        self.bounds = bounds
        self.numparams = numparams
        self.returns = returns


class SSBDecompiler:
    VIRTUAL_SWITCH_START_VAL = (0x50,)
    VIRTUAL_SWITCH_DEFAULT_VAL = (0x51,)
    VIRTUAL_SWITCH_BREAK_VAL = (0x52,)

    class DecompNode:
        def __init__(self, val):
            self.children = []
            self.parent = None
            self.val = val

        def __repr__(self):
            return str(self.val)

        def add_child(self, child):
            self.children.append(child)
            child.parent = self
            return child

        def pop_child(self):
            self.children[-1].parent = None
            return self.children.pop()

    @staticmethod
    def tokenize(ints, startoffset, endoffset=-1):
        # every int gets its own token except the 0x0F command
        # the token is the opcode and then the params
        # for almost every command this is the first byte, the second byte, and the last 2 bytes

        tokens = []

        i = startoffset
        while endoffset == -1 or i <= endoffset:
            cmd = ints[i]
            oc = cmd & 0xff

            if oc == 0x0f:
                token = (oc, to_signed(ints[i + 1], 0x20), i)
                i += 1
            elif oc == 0x1f:
                token = (oc, cmd >> 0x8, i)
            elif oc == 0x01:
                token = (oc, (cmd >> 0x8) & 0xff, cmd >> 0x1c, (cmd >> 0x10) & 0x0fff, i)
            else:
                token = (oc, (cmd >> 0x8) & 0xff, cmd >> 0x10, i)

            # deal with signs
            if oc in (0x03, 0x07, 0x09, 0x0a):  # second param is signed
                token = (token[0], token[1], to_signed_16(token[2]), token[-1])
            elif oc == 0x1f:  # special
                token = (token[0], to_signed(token[1], 24), token[-1])

            tokens.append(token)

            if endoffset == -1 and oc == 0x05 and ints[i + 1] & 0xff != 0x05:
                break

            i += 1

        return tokens

    class VarSymbol:
        # TODO: add more customization for symbols
        # NOTE: never put the location on stack in here
        def __init__(self, index, stack_pos, data=None):
            self.start_index = index
            self.stack_pos = stack_pos
            self.data = data
    
    @staticmethod
    def create_lvar_binding(_json: list[dict]):
        # each element in the list is a binding
        binding = dict()
        for elem in _json:
            start_index = elem["start_index"]
            stack_pos = elem["stack_pos"]
            symbol_dat = elem["symbol_dat"]
            binding.setdefault(start_index, []).append(SSBDecompiler.VarSymbol(start_index, stack_pos, symbol_dat))
        return binding
    
    """
    DOES NOT ACTUALLY CREATE JSON
    """
    @staticmethod
    def create_json_from_binding(binding: dict[int, list[VarSymbol]]):
        out = []
        for indx in binding:
            for symbol in binding[indx]:
                out.append({"start_index": indx, "stack_pos": symbol.stack_pos, "symbol_dat": symbol.data})
        return out

    @staticmethod
    def get_var_name(stackpos, stackvar_names: list[VarSymbol]):
        max_st_index = -1
        name = ""
        for vsym in stackvar_names:
            if vsym.stack_pos == stackpos and vsym.start_index > max_st_index:
                max_st_index = vsym.start_index
                name = vsym.data["name"]

        if max_st_index != -1:
            return name
        elif stackpos >= 0:
            return'param_{:x}'.format(stackpos)
        else:
            return 'local_{:x}'.format(-stackpos - 1)

    # stackvar_names is a list of all currently applied symbols
    @staticmethod
    def str_token(token, stackvar_names: list[VarSymbol] = None, getfunction_callback = None):
        if stackvar_names is None:
            stackvar_names = []
        opcode = token[0]
        if opcode == 0x00:
            return 'nop'
        elif opcode == 0x01:
            return 'int [{:1x}][{:03x}] ({:02x} params)'.format(token[2], token[3], token[1])
        elif opcode == 0x02:
            return 'throw {:02x}'.format(token[2])
        elif opcode == 0x03:
            if getfunction_callback is None:
                return 'call {:+04x} ({:02x} params)'.format(token[2], token[1])
            else:
                f: SSBFunc = getfunction_callback(token[-1] + token[2] + 1)
                return 'call {} ({:02x} params)'.format(f.name, token[1])
                # COMECOME
        elif opcode == 0x04:
            return '0x04 {:04x}'.format(token[2])
        elif opcode == 0x05:
            return '{} (pop {:04x})'.format('end' if token[1] == 0 else 'ret', token[2])
        elif opcode == 0x06:
            return 'alloc {:04x}'.format(token[2])
        elif opcode == 0x07:
            if token[1] == 1:
                cmdname = 'jumpnz'
            elif token[1] == 2:
                cmdname = 'jumpz'
            elif token[1] == 3:
                cmdname = 'jumpz(error)'
            else:
                cmdname = 'ujump'
            return '{} {:+04x}'.format(cmdname, token[2])
        elif opcode == 0x08:
            return 'case {:02x}: (else j {:+04x})'.format(token[1], token[2])
        elif opcode == 0x09:
            stackpos = token[2]
            fname = SSBDecompiler.get_var_name(stackpos, stackvar_names)
            return 'push stack[{:+04x}] ({})'.format(stackpos, fname)
        elif opcode == 0x0a:
            mod = token[1]
            if mod == 0:
                cmdname = 'pop (set)'
            elif mod == 1:
                cmdname = 'pop (add)'
            else:
                cmdname = 'pop (sub)'
            stackpos = token[2]
            fname = SSBDecompiler.get_var_name(stackpos, stackvar_names)
            return '{} stack[{:+04x}] ({})'.format(cmdname, stackpos, fname)
        elif opcode == 0x0d:
            return 'del {:04x}'.format(token[2])
        elif opcode == 0x0e:
            return 'pushw {:04x}'.format(token[2])
        elif opcode == 0x0f:
            return 'pushdw {:08x}'.format(token[1])
        elif opcode == 0x10:
            return 'push return'
        elif opcode == 0x11:
            return 'push str {:+04x}'.format(token[2])
        elif opcode == 0x12:
            return 'add'
        elif opcode == 0x13:
            if token[2] == 0:
                return 'sub (stack[-1] - stack[0])'
            else:
                return 'sub (stack[0] - stack[-1])'
        elif opcode == 0x14:
            return 'mult'
        elif opcode == 0x15:
            if token[2] == 0:
                return 'div (stack[-1] / stack[0])'
            else:
                return 'div (stack[0] / stack[-1])'
        elif opcode == 0x16:
            if token[2] == 0:
                return 'mod (stack[-1] % stack[0])'
            else:
                return 'mod (stack[0] % stack[-1])'
        elif opcode == 0x17:
            R = ['==', '!=', '>', '<', '>=', '<=', 'hasflags'][token[2]]
            if token[1] == 0:
                return 'test (stack[-1] {} stack[0])'.format(R)
            else:
                return 'test (stack[0] {} stack[-1])'.format(R)
        elif opcode == 0x18:
            return 'and'
        elif opcode == 0x19:
            return 'or'
        elif opcode == 0x1a:
            return 'xor'
        elif opcode == 0x1b:
            return 'compliment'
        elif opcode == 0x1c:
            return 'neg'
        elif opcode == 0x1d:
            return 'not'
        elif opcode == 0x1e:
            return 'bitshift by {:04x}'.format(token[2])
        elif opcode == 0x1f:
            return 'ptr {:+06x}'.format(token[1])
        return 'command not recognized'

    @staticmethod
    def get_num_consumed(token):
        if token[0] in (0x01, 0x03, 0x05, 0x0d):
            return token[1]
        if token[0] in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1e):
            return 2
        if token[0] in (0x0a, 0x10, 0x1b, 0x1c, 0x1d):  # (0x10 is a dirty hack)
            return 1
        if token[0] == 0x07:
            return 1 if token[1] in (1, 2, 3) else 0
        return 0

    # 1 is forward
    # bound is how many items to go through (number of statements contained for a control seq, parameters for
    @staticmethod
    def create_decomp_tree(tokens, root=None, i=0):
        # TODO: make not recursive
        # TODO: add other control statements
        if root is None:
            root = SSBDecompiler.DecompNode(None)

        parent = root
        bound_stack = [-1]

        # what we'll do for calls is simply recursively fill them
        # for
        while i < len(tokens):
            # hangle
            curr = tokens[i]
            curr_node = SSBDecompiler.DecompNode(curr)

            consumed = SSBDecompiler.get_num_consumed(curr)
            while consumed:
                curr_node.add_child(parent.pop_child())
                consumed -= 1

            if curr[0] == 0x08:  # case statement
                if parent.val != SSBDecompiler.VIRTUAL_SWITCH_START_VAL:  # first case statement
                    print('creating switch decomp tree...')
                    # process switch statement
                    virt_node = SSBDecompiler.DecompNode(SSBDecompiler.VIRTUAL_SWITCH_START_VAL)  # create switch
                    virt_node.add_child(parent.pop_child())  # add last value
                    parent = parent.add_child(virt_node)  # push switch
                    bound_stack.append(-1)  # push dummy bound

                print('(at next case: {})'.format(curr_node))
                # start decompliation at the next index, up until
                parent = parent.add_child(curr_node)
                bound_stack.append(i + curr[2])
            else:
                if parent.val == SSBDecompiler.VIRTUAL_SWITCH_START_VAL:  # in switch but not a case, so default
                    # default
                    virt_node = SSBDecompiler.DecompNode(SSBDecompiler.VIRTUAL_SWITCH_DEFAULT_VAL)
                    print('now defaults')
                    parent = parent.add_child(virt_node)  # set parent to default statement
                    bound_stack.append(bound_stack[-1])  # same end as switch

                parent.add_child(curr_node)  # TODO: don't add breaks? (and ends of conditionals?)

            # remember to decrement processing_bound and inc i
            if parent.val is not None and parent.val[0] == 0x08:  # is switch case
                if bound_stack[-1] - i == 0:  # at end of switch statement (break)
                    # get end of switch
                    print('at end of switch')
                    if curr[0] == 0x07 and curr[1] not in (1, 2, 3):  # ujump (break)
                        print('found break')
                        # exit case
                        parent = parent.parent
                        bound_stack.pop()
                        bound_stack[-1] = i + curr[2]  # set switch end
                        print('set switch end to {}'.format(bound_stack[-1]))

            print('tree is: \n{}\ni: {}\nbounds: {}\n'.format(
                SSBDecompiler.str_parsetree(parent), i, bound_stack))
            while bound_stack[-1] == i:
                parent = parent.parent
                bound_stack.pop()
            i += 1

        return root

    @staticmethod
    def str_parsetree(root, level=0, seen=None):
        """
        debug printout
        """
        tabs = '\t' * level
        valstr = str(root.val)
        if seen is None:
            seen = set()
        if root in seen:
            return '{}recursive ref to node with val {}'.format(tabs, valstr)
        seen.add(root)
        if root.val == SSBDecompiler.VIRTUAL_SWITCH_START_VAL:
            valstr = 'switch'
        elif root.val == SSBDecompiler.VIRTUAL_SWITCH_DEFAULT_VAL:
            valstr = 'default'
        if len(root.children) > 0:
            return '{}{}:\n {}'.format(tabs, valstr,
                                       ',\n'.join(SSBDecompiler.str_parsetree(f, level + 1) for f in root.children))
        else:
            return '{}{}'.format(tabs, valstr)

    @staticmethod
    def decompile(commands):
        pass


def test_decompile_no_forks():
    s = struct.Struct('<I')
    commands = [s.unpack(b'\x01\x00\x23\x45')[0],
                s.unpack(b'\x0e\x00\x20\xef')[0],
                s.unpack(b'\x0e\x00\x2f\xf0')[0],
                s.unpack(b'\x01\x02\x00\x00')[0],
                s.unpack(b'\x10\x00\x00\x00')[0],
                s.unpack(b'\x0e\x00\x20\xef')[0],
                s.unpack(b'\x01\x01\x00\x00')[0],
                s.unpack(b'\x10\x00\x00\x00')[0],
                s.unpack(b'\x01\x02\x11\x11')[0],
                s.unpack(b'\x10\x00\x00\x00')[0],
                s.unpack(b'\x05\x01\x00\x00')[0]]
    print(commands)
    tokens = SSBDecompiler.tokenize(commands, 0, len(commands) - 1)
    print(tokens)
    # return (00_00(20_ef))
    root = SSBDecompiler.create_decomp_tree(tokens)
    print(SSBDecompiler.str_parsetree(root))


def test_decompile_switch():
    s = struct.Struct('<I')
    commands = [
        s.unpack(b'\x09\x00\x00\x00')[0],
        s.unpack(b'\x08\x00\x01\x00')[0],  # case 0
        s.unpack(b'\x07\x00\x03\x00')[0],  # break
        s.unpack(b'\x08\x01\x01\x00')[0],  # case 1
        s.unpack(b'\x07\x00\x01\x00')[0],  # break
        s.unpack(b'\x0d\x00\x01\x00')[0],  # default
        s.unpack(b'\x01\x00\x02\x00')[0],
        s.unpack(b'\x01\x00\x02\x00')[0],
        s.unpack(b'\x05\x00\x00\x00')[0],
    ]
    print(commands)
    tokens = SSBDecompiler.tokenize(commands, 0, len(commands) - 1)
    print(tokens)
    root = SSBDecompiler.DecompNode(None)
    # return (00_00(20_ef))
    SSBDecompiler.create_decomp_tree(tokens, root)
    print(SSBDecompiler.str_parsetree(root))


class HookType:
    FUNCTION = 0
    UCJUMP = 1


class Hooking:  # container class for a hooking
    @staticmethod
    def from_dict(dct):
        return Hooking(dct['original_offset'], dct['original_command'],
                       dct['hook_offset'], dct['hook_length'],
                       dct.get('hook_type', HookType.FUNCTION), dct.get('num_args', 0),
                       dct.get('allocated', False), dct.get('activated', False),
                       dct.get('description', ''))

    @staticmethod
    def to_dict(obj):
        return {
            'original_offset': obj.original_offset,
            'original_command': obj.original_command,
            'hook_offset': obj.hook_offset,
            'hook_length': obj.hook_length,
            'hook_type': obj.hook_type,
            'num_args': obj.num_args,
            'description': obj.description
        }

    def __init__(self, original_offset, original_command, hook_offset, hook_length, hook_type=HookType.FUNCTION,
                 num_args=0, allocated=False, activated=False, description=''):
        """
        original_offset: offset in bytes of the location to be hooked
        original_command: 4-byte integer representing the command to be replaced
        hook_offset: offset IN BYTES of the new command
        hook_length: length IN BYTES of the new command (including return)
        """
        self.original_offset = original_offset
        self.original_command = original_command
        self.hook_offset = hook_offset
        self.hook_length = hook_length
        self.hook_type = hook_type
        self.num_args = num_args
        self.allocated = allocated
        self.activated = activated
        self.description = description

    def as_usable_command(self, e):
        """
        e: bytes object with hook body
        """
        if len(e) > self.hook_length - 8:  # too long for start and end
            return bytes(0)
        else:
            return struct.pack('<I', self.original_command) + e + b'\x05\x00\x00\x00'

    def allocate(self, buf):
        """
        Trunticate the buffer so there's enough space for this command
        Returns new file size (or -1 if failed)
        """
        eof = len(buf)  # actual
        _eof = self.hook_offset + self.hook_length  # needed
        # if space is already allocated, do nothing
        if eof >= _eof:
            return eof
        # move in enough space
        extension = bytes(_eof - eof)
        print(f'extension is {extension}, eof is {hex(eof)}, offset is {hex(self.hook_offset)}')
        buf.extend(extension)
        _eof = len(buf)
        if eof == _eof:
            self.allocated = True
        # trunticate file
        return len(buf)

    def free(self, buf):
        """
        Free the area used, delete to original length
        """

        # if already smaller don't do anything
        # if larger, uhh
        # idk implement this later ig
        pass

    def activate(self, buf, command):
        """
        Writes command into allocated space, inserts jump
        buf: buffer to write to
        command: PACKED bytes object to write
        """
        if self.hook_type == HookType.FUNCTION:
            int_offset_to_self = (self.hook_offset - self.original_offset - 1) // 4
            # write hook into original
            print(int_offset_to_self)
            struct.pack_into('<BBh', buf, self.original_offset, 0x03, self.num_args, int_offset_to_self)
            # write command in allocated space
            # prolly a better way with memoryview
            buf[self.hook_offset:self.hook_offset + min(self.hook_length, len(command))] = command
            return len(command) + 1
        return -1

    def remove(self, buf):
        """
        buf: buffer to return original command to
        """
        if self.hook_type == HookType.FUNCTION:
            # write original byte back in
            struct.pack_into('<I', buf, self.original_offset, self.original_command)
            # clear space used for the hook
            buf.seek(self.hook_offset, 0)
            self.activated = False
            return 1
        return -1


class SSBFile:
    class SSBFuncTable:
        def __init__(self):
            self.hashtable: dict = dict()

        def add(self, key, value):
            if key in self.hashtable:
                self.hashtable[key].insert(0, value)
            else:
                self.hashtable[key] = [value]

        def set_visible(self, key, value):
            if key in self.hashtable:
                self.hashtable[key][0] = value

        def get_visible(self, key):
            if key in self.hashtable:
                return self.hashtable[key][0]
            else:
                return None

        def set_all(self, key, value):
            self.hashtable[key] = value

        def get_all(self, key):
            return self.hashtable[key]

        def __setitem__(self, key, value):
            self.set_visible(key, value)

        def __getitem__(self, key):
            return self.get_visible(key)

        def __len__(self):
            s = 0
            for key in self.hashtable:
                s += len(self.hashtable[key])
            return s

        def __contains__(self, item):
            return item in self.hashtable

        def __iter__(self):
            return self.hashtable.__iter__()

        def pop(self, key):
            return self.hashtable.pop(key)

    class SSBHeader:
        def __init__(self, bytes):
            unpacked = struct.unpack('<8I', bytes)
            self.id, self.functable_offset, self.strings_offset, _, _, self.bitmask, self.bitmask1, _ = unpacked

        def get_bytes(self):
            return struct.pack('<8I', self.id, self.functable_offset, self.strings_offset, self.strings_offset,
                            0, self.bitmask, self.bitmask1, 0)

    @staticmethod
    def read_header(f):
        f.seek(0, 0)  # seek file start
        data = f.read(0x20)
        return SSBFile.SSBHeader(data)  # read in bytes

    @staticmethod
    def read_data(f, header):
        data = []
        offset = 0x20
        f.seek(offset, 0)
        end = header.functable_offset
        while True:
            bytes_read = f.read(4)
            if len(bytes_read) < 4 or offset >= end:
                break
            data.append(struct.unpack('<I', bytes_read)[0])
            offset += 4
        return data

    @staticmethod
    def read_functable(f, header):
        functable = SSBFile.SSBFuncTable()
        # get and seek offset
        offset = header.functable_offset
        f.seek(offset, 0)
        # get end
        end = header.strings_offset
        # read table in
        while True:
            bytes_read = f.read(12)
            if len(bytes_read) < 12 or offset >= end:
                break
            ints = struct.unpack('<3I', bytes_read)
            # convert to string: (offset of function, raw ints, offset of entry)
            functable.add(convert_int(ints[0]) + convert_int(ints[1]), (ints[2] - 8, ints[0:2], offset))
            offset += 12

        return functable

    @staticmethod
    def read_strings(f, header, end):
        # returns a hashmap of string offsets and string contents
        if end == -1:
            f.seek(0, 2)
            end = f.tell()

        offset = header.strings_offset
        f.seek(offset, 0)
        curr_str = b''
        strings = dict()
        start_offset = 0

        while True:
            bytes_read = f.read(1)
            if len(bytes_read) < 1 or offset >= end:
                break
            next_byte = bytes_read[0]
            curr_str += bytes_read
            if next_byte == 0:
                strings[start_offset] = curr_str
                curr_str = b''
                start_offset = offset - header.strings_offset + 1
            offset += 1
        return strings

    def get_next_aligned_offset(self):
        return self.eof + (4 - self.eof % 4)

    def __init__(self, f, str_end=-1):
        f.seek(0, 2)  # seek end
        self.eof = f.tell()
        self.header = SSBFile.read_header(f)
        self.data = SSBFile.read_data(f, self.header)
        self.functable = SSBFile.read_functable(f, self.header)
        self.strings = SSBFile.read_strings(f, self.header, str_end)
        self.var_symbols: dict[int, list[SSBDecompiler.VarSymbol]] = dict()   # Variable symbols. Need to be bound
        self.raw_symbols = dict()   # all symbols associated with this ssb file

    def write_to_stream(self, stream):
        # DOES NOT WORK
        # assume at start of stream
        stream.write(self.header.get_bytes())
        for packet in self.data:
            stream.write(struct.pack('<I', packet))

    def write_to_buffer(self, buffer: bytearray):
        header_bytes = self.header.get_bytes()
        buffer[0:0x20] = header_bytes

        for i in range(len(self.data)):
            start = 0x20 + (i * 0x4)
            buffer[start:start+0x4] = self.data[i].to_bytes(4, byteorder='little')
        pos = self.header.functable_offset
        for key in self.functable.hashtable:
            for val in self.functable.hashtable[key]:
                pos = val[2]
                buffer[pos:pos + 12] = struct.pack('<3I', val[1][0], val[1][1], val[0] + 8)

        for offset in self.strings:
            s = self.strings[offset]
            r_offset = offset + self.header.strings_offset
            buffer[r_offset:r_offset + len(s)] = s
    """
    takes in the raw json object from the symbol file and binds it
    """
    def bind_symbol_dict(self, symbols):
        self.raw_symbols = symbols
        self.rebind()

    def rebind(self):
        # NOTE: in the future we may want that bindings are more complex, so perhaps instead of a dictionary we use our own class?
        # ALSO the idea is that we have {start line: {stack position: symbol}}
        self.var_symbols = SSBDecompiler.create_lvar_binding(self.raw_symbols)
    
    def update_raw(self):
        self.raw_symbols = SSBDecompiler.create_json_from_binding(self.var_symbols)

    # allocating functions
    """
    start_instr: index of instruction you wish to allocate after. ie, if this is the end of a function you are creating a new one
    """
    def insert_instrs(self, data_size: int, start_instr: int = -1, data_to_ins: list = None):
        # insert 0's into list
        if data_size <= 0:
            return  # nothing to do
        if start_instr == -1 or start_instr > len(self.data):
            start_instr = len(self.data)
        if data_to_ins is None:
            data_to_ins = [0] * data_size  # fill with 0s
        for i in range(len(self.data)):
            jmp_offset = get_jump_offset(self.data[i])
            if jmp_offset is not None:
                if 0 <= (start_instr - i) < jmp_offset:
                    # if it jumps from before to after, add size
                    print(f"old: {self.data[i]:08X}, size: {data_size}")
                    new_data = set_jump_offset(self.data[i], jmp_offset - 1 + data_size)
                    self.data[i] = new_data
                    print(f"new: {new_data:08X}")
                elif jmp_offset <= (start_instr - i) < 0:
                    # decrease jump
                    print(f"old: {self.data[i]:08X}, size: {data_size}")
                    new_data = set_jump_offset(self.data[i], jmp_offset - 1 - data_size)
                    self.data[i] = new_data
                    print(f"new: {new_data:08X}")
        # insert actual data
        for a in data_to_ins:
            self.data.insert(start_instr + 1, a)  # not correct, will reverse them
        # update bound symbols
        for obj in self.raw_symbols:
            if obj["start_indx"] >= start_instr:
                obj["start_indx"] = obj["start_indx"] + data_size
        self.rebind()
        # update the function table
        for fun_name in self.functable:
            if self.functable[fun_name][0] > start_instr:
                self.functable[fun_name] = (self.functable[fun_name][0] + data_size,
                                            self.functable[fun_name][1],
                                            self.functable[fun_name][2] + data_size * 4)
            else:
                self.functable[fun_name] = (self.functable[fun_name][0],
                                            self.functable[fun_name][1],
                                            self.functable[fun_name][2] + data_size * 4)
                # print(self.functable[fun_name])
        # update the ftable and string offsets
        self.header.functable_offset += data_size * 4
        self.header.strings_offset += data_size * 4

    def insert_functable_entry(self, fname, offset, table_indx: int = -1):
        if table_indx == -1:
            table_indx = len(self.functable)
        table_offset = self.header.functable_offset + table_indx * 12
        # push forward function table
        for fun_name in self.functable:
            if self.functable[fun_name][1] >= table_offset:
                self.functable[fun_name] = (self.functable[fun_name][0],
                                            self.functable[fun_name][1],
                                            self.functable[fun_name][2] + 12)
        self.functable[fname] = (offset, convert_str(fname), table_offset)

    def get_function_bounds(self, target):
        endindex = target
        # get end
        while endindex < len(self.data) and self.data[endindex] & 0xff != 0x05:
            endindex += 1
        # get start
        startindex = target
        while True:
            if startindex <= 0:
                break
            elif self.data[startindex] & 0xff == 0x05:
                startindex += 1
                break
            startindex -= 1

        return startindex, endindex

    def get_function_end(self, start):
        while start < len(self.data) and self.data[start] & 0xff != 0x05:
            start += 1
        if start + 1 < len(self.data) and self.data[start + 1] & 0xff == 0x05:
            start += 1
        return start

    def autocalc_params(self, position: int):
        return 0


def open_ssb(filename, mode='rb'):
    return open(os.path.join(mod_fileroot, filename), mode=mode, buffering=0)


def save_ssb(filename, b):
    fl = open_ssb(filename, mode='w+b')
    ret = fl.write(b)
    fl.close()
    return ret


def json_to_hooks(dct):
    for fname in dct:
        narray = []
        array = dct[fname]
        for hook_dct in array:
            narray.append(Hooking.from_dict(hook_dct))
        dct[fname] = narray
    return dct


def hooks_to_json(dct):
    for fname in dct:
        narray = []
        array = dct[fname]
        for hook_obj in array:
            narray.append(Hooking.to_dict(hook_obj))
        dct[fname] = narray
    return dct


def to_signed(n, l):
    return n | (- (n & (1 << (l - 1))))


def to_signed_16(n):
    return n | (- (n & 0x8000))


def set_jump_offset(cmd, new_offset):
    opcode = (cmd & 0xff).to_bytes(1)
    byte2 = ((cmd >> 0x8) & 0xff).to_bytes(1)
    if new_offset > 0xffffff:
        print('oops')
        return cmd
    if opcode == 0x1f:
        return int.from_bytes(struct.pack("<ci", opcode, new_offset)[0:4], byteorder='little')
    elif new_offset > 0xffff:
        print('bad')
        return cmd
    else:
        return int.from_bytes(struct.pack("<cch", opcode, byte2, new_offset), byteorder='little')


def get_jump_offset(cmd):
    opcode = cmd & 0xff
    if opcode == 0x07:
        # ujump
        return to_signed_16(cmd >> 0x10) + 1
    elif opcode == 0x03:
        return to_signed_16(cmd >> 0x10) + 1
    elif opcode == 0x08:
        return to_signed_16(cmd >> 0x10) + 1
    elif opcode == 0x1f:
        return to_signed(cmd >> 8, 0x18) + 1
    return None
