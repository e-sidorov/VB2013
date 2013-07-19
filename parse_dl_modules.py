import os
import sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    print "[E] Module 'pyelftools' wasn't found! Please install it before running this script!"
    sys.exit(1)


def bytes2str(b):
    return b.decode('latin-1')


class ReadElf(object):
    def __init__(self, file):
        self.file = ELFFile(file)

    def get_symbol_tables(self):
        symbols = {}
        for section in self.file.iter_sections():
            if isinstance(section, SymbolTableSection) and section['sh_entsize']:
                for nsym, symbol in enumerate(section.iter_symbols()):
                    sym_name = bytes2str(symbol.name)
                    if sym_name in ['KEY_XOR', 'C_CC_HOST', 'C_CC_URI']:
                        symbols[sym_name] = \
                            (
                                symbol['st_value'] if self.file.elfclass == 32 else (symbol['st_value'] % 65536),
                                symbol['st_size']
                            )
        return symbols

    def get_soname(self):
        so_name = None
        for section in self.file.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == 'DT_SONAME':
                        so_name = bytes2str(tag.soname)
        return so_name


def file_read_binary(filename, pos, size):
    buff = None
    try:
        if os.path.isfile(filename):
            with open(filename, "rb") as f:
                f.seek(pos)
                buff = f.read(size)
    except:
        pass
    return buff


def xor_decrypt(enc_buff, size, xor_key):
    dec_buff = ''
    for i in xrange(size):
        dec_buff += chr(ord(enc_buff[i]) ^ xor_key[i % len(xor_key)])
    return dec_buff


def find_files(path):
    return [os.path.join(root, item) for root, dirs, files in os.walk(path) for item in files]


def usage(name):
    print 'Usage: %s <path to folder to process>\n' % name


def main(argv):
    print "This script analyses a folder with DarkLeech modules and"
    print "decrypts and prints C&C URI and module name for each module."
    print "Authors:"
    print "\t Andrey Rassokhin ( gizmo@yandex-team.ru )"
    print "\t Evgeniy Sidorov ( e-sidorov@yandex-team.ru )"
    print "*****************************************************************"

    if len(argv) < 2:
        print "You must specify a folder to process."
        usage(argv[0])
        sys.exit(1)

    if argv[1] in ('--help', '-h'):
        usage(argv[0])
        sys.exit(0)

    path = argv[1]
    if not os.path.isdir(path):
        print "[E] %s is not a directory" % path
        sys.exit(1)

    fileList = find_files(path)

    for filename in fileList:
        cc_host = ""
        cc_uri = ""

        with open(filename, 'rb') as fl:
            try:
                readelf = ReadElf(fl)
                sym_dict = readelf.get_symbol_tables()

                if "KEY_XOR" in sym_dict and "C_CC_HOST" in sym_dict and "C_CC_URI" in sym_dict:
                    offset, size = sym_dict["KEY_XOR"]
                    xor_key = map(ord, file_read_binary(filename, offset, size))

                    offset, size = sym_dict["C_CC_HOST"]
                    buff = file_read_binary(filename, offset, size)
                    if buff is not None:
                        cc_host = xor_decrypt(buff, size, xor_key)

                    offset, size = sym_dict["C_CC_URI"]
                    buff = file_read_binary(filename, offset, size)
                    if buff is not None:
                        cc_uri = xor_decrypt(buff, size, xor_key)

                    soname = readelf.get_soname()

                    print "[~] File: %s Module: %s C&C: %s%s" % (filename, soname, cc_host, cc_uri)
            except:
                pass

    return

if __name__ == '__main__':
    main(sys.argv)
