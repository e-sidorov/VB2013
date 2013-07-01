# script for DarkLeech modules parsing
# authors:
# Andrey Ressokhin ( gizmo@yandex-team.ru )
# Evgeny Sidorov ( e-sidorov@yandex-team.ru )

# Import
import os
import sys

# From
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    print "[E] Module 'pyelftools' wasn't found! Please install it before running this script!"
    sys.exit( 1 )

def bytes2str(b): return b.decode('latin-1')

class ReadElf(object):
    def __init__(self, file):
        self.file = ELFFile(file)

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True):
        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.file.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def get_symbol_tables(self):
        symbols = {}
        for section in self.file.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                continue
            for nsym, symbol in enumerate(section.iter_symbols()):
                sym_name = bytes2str(symbol.name)
                if sym_name in ['KEY_XOR', 'C_CC_HOST', 'C_CC_URI']:
                    if self.file.elfclass == 32:
                        symbols[ sym_name ] = ( symbol['st_value'], symbol['st_size'] )
                    else:
                        symbols[ sym_name ] = ( int( self._format_hex( symbol['st_value'], fullhex=True, lead0x=False)[-4:], 16 ), symbol['st_size'] )
            return symbols

    def get_soname(self):
        so_name = None
        for section in self.file.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            padding = 20 + (8 if self.file.elfclass == 32 else 0)
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_SONAME':
                    so_name = bytes2str(tag.soname)
        return so_name

# Read binary file for WinNT
def file_read_binary( filename, pos, size ):
    buff = None
    try:
        if os.path.isfile( filename ):
            with open( filename, "rb") as f:
                f.seek( pos )
                byte = f.read(1)
                if byte:
                    if ord( byte ) == 10:
                        buff = chr( 10 )
                    else:
                        buff = byte
                while 1:
                    byte = f.read(1)
                    if  not byte or \
                        len( buff ) == size:
                        break
                    if ord( byte ) == 10:
                        buff += chr( 10 )
                    else:
                        buff += byte
    except Exception, e:
        print e
        pass
    #print filename, buff
    return buff

def xor_decrypt( enc_buff, size, xor_key ):
    dec_buff    = ''
    for i in xrange( 0, size ):
        dec_buff += chr( ord( enc_buff[ i ] ) ^ xor_key[ i % len( xor_key ) ] )
    return dec_buff

def find_files( path, ext=None ):
    logs = []
    for root, dirs, files in os.walk( path ):
        for item in files:
            if ext is not None:
                if item.endswith( ext ):
                    logs.append( os.path.join( root, item ) )
            else:
                logs.append( os.path.join( root, item ) )
    return logs

def main( argv ):

    path = argv[1]
    if not os.path.isdir( path ):
        print "[E] %s is not directory" % path
        sys.exit( 1 )

    fileList = find_files( path )
    #print fileList

    for filename in fileList:

        cc_host = ""
        cc_uri = ""
        soname = ""
        xor_key = []
        symDict = {}

        with open( filename, 'rb' ) as file:
            try:
                readelf = ReadElf( file )
                symDict = readelf.get_symbol_tables(  )

                for item in [ "KEY_XOR", "C_CC_HOST", "C_CC_URI" ]:
                    if not symDict.has_key( item ):
                        break

                #print symDict

                offset, size = symDict.get( "KEY_XOR" )
                for i in xrange( 0, size ):
                    k = file_read_binary( filename, offset + i, 1 )
                    if k != None:
                        xor_key.append( ord( k ) )

                offset, size = symDict.get( "C_CC_HOST" )
                buff = file_read_binary( filename, offset, size )
                if buff != None:
                    cc_host = xor_decrypt( buff, size, xor_key )

                offset, size = symDict.get( "C_CC_URI" )
                buff = file_read_binary( filename, offset, size )
                if buff != None:
                    cc_uri = xor_decrypt( buff, size, xor_key )

                soname = readelf.get_soname(  )

                print "[~] File: %s Module: %s C&C: %s%s" % ( filename, soname, cc_host, cc_uri )
            except Exception, e:
                print filename, e
                pass

    return

if __name__ == '__main__':
    main( sys.argv )
    sys.exit( 1 )
#-------------------------------------------------------------------------------
# EoF