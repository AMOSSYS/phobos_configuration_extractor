from enum import IntEnum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
 
import idc
import ida_bytes
import ida_name
 
class CONFIG_INDEX_ENUM(IntEnum):
    CONFIG_HASH                              =  0
    CONFIG_SIZE                              =  1
    EMBEDDED_RSA_KEY                         =  2
    FLAGS                                    =  3
    RANSOM_FILE_EXTENSION                    =  4
    RESERVED                                 =  5
    TARGET_EXTENSIONS                        =  6
    BLACKLIST_EXTENSIONS                     =  7
    BLACKLIST_FILES                          =  8
    BLACKLIST_FOLDERS                        =  9
    PROCESS_KILL_LIST                        = 10
    RANSOM_NOTE_NAME_HTA                     = 11
    RANSOM_NOTE_NAME_TXT                     = 12
    RANSOM_NOTE_HTA                          = 13
    RANSOM_NOTE_TXT                          = 14
    TARGET_FOLDER_DESKTOP                    = 15
    TARGET_FOLDER_APPDATA                    = 16
    REG_PERSOST_KEY                          = 17
    TARGET_FOLDER_STARTUP                    = 18
    RESERVED_HASH1                           = 19
    MSG_ALPHABET                             = 20
    API_RUNAS                                = 21
    API_OPEN                                 = 22
    TARGET_FOLDER_SYSDRIVE                   = 23
    TARGET_FOLDER_TEMP                       = 24
    MUTEX_NAME                               = 25
    API_KERNEL32_DISABLEWOW64FSREDIR         = 26
    API_KERNEL32_GETFINALPATHNAMEBYHANDLEW   = 27
    API_SEDEBUGPRIVILEGE                     = 28
    API_SEBACKUPPRIVILEGE                    = 29
    API_QUERYINFORMATIONPROCESS              = 30
    EXPLORER_EXE                             = 31
    API_SHCREATEITEMFROMPARSINGNAME          = 32
    UAC_ELEVATION_CLSID                      = 33
    BLACKLIST_DOTNET_PATH                    = 34
    HKEY_CURRENT_BUILD                       = 35
    HKEY_UAC_CONSENTPROMPTBEHAVIORADMIN      = 36
    API_ISWOW64PROCESS                       = 37
    API_COMPMGMT                             = 38
    API_CREATEPROCESSWITHTOKENW              = 39
    TARGET_FILDER_USERSHELL                  = 40
    FOLDER_COMSPEC                           = 41
    CMD_DELETE_BKP                           = 42
    CMD_OPEN_FIREWALL                        = 43
    CMD_ADITIONAL1                           = 44
    RESERVED2                                = 45
    RESERVED3                                = 46
    PE_EMBEDDED_32BIT                        = 47
    PE_EMBEDDED_64BIT                        = 48
    FEATURES_FLAG                            = 49
    RESERVED_HASH2                           = 50
    VERSION_ID                               = 51
    MSG_LOCAL_THREAD_START                   = 52
    MSG_LOCAL_THREAD_STOP                    = 53
    MSG_USER_THREAD_START                    = 54
    MSG_USER_THREAD_STOP                     = 55
    MSG_DRIVE_SCAN_START                     = 56
    MSG_DRIVE_SCAN_STOP                      = 57
    MSG_NETWORK_SCAN_START                   = 58
    MSG_NETWORK_SCAN_STOP                    = 59
    MSG_NETWORK_SCAN_COMPLETE                = 60
    MSG_PROC_WATCHDOG_START                  = 61
    MSG_PROC_WATCHDOG_STOP                   = 62
    MSG_INSTANCE_SYNC_START                  = 63
    MSG_INSTANCE_SYNC_STOP                   = 64
    MSG_PLUS                                 = 65
    MSG_MINUS                                = 66
    DEBUG_FILE_NAME                          = 67
    CFG_USERNAME                             = 68
    CFG_HTTP_PATH                            = 69
    CFG_OPT_DATA                             = 70
 
class Payload_header_t:
    def __init__(self, header_name):
        self.header_addr = ida_name.get_name_ea(idc.BADADDR, header_name)
        self.payload_offset = ida_bytes.get_dword(self.header_addr)
        self.payload_addr = self.header_addr + self.payload_offset
        self.payload_size = ida_bytes.get_dword(self.header_addr + 4)
        self.AES_key = ida_bytes.get_bytes(self.header_addr + 8, 32)
        self.payload_CRC32 = ida_bytes.get_dword(self.header_addr + 0x28)
        
    def __str__(self):
        return_string = "\tHEADER:\n"
        return_string += f"\t\t header addr:  {hex(self.header_addr)}\n"
        return_string += f"\t\t payload addr: {hex(self.payload_addr)}\n"
        return_string += f"\t\t AES key:      {self.AES_key.hex()}\n"
        return return_string
 
class Conf_header_t:
    def __init__(self, header_start):
        self.index = ida_bytes.get_dword(header_start)
        self.offset = ida_bytes.get_dword(header_start+4)
        self.size = ida_bytes.get_dword(header_start+8)
        
class Phobos_conf_t:
    def __init__(self, buffer_addr, size, entry_count, AES_key):
        self.header = {}
        self.entry_count = entry_count
        for i in range(entry_count):
            self.header[CONFIG_INDEX_ENUM(ida_bytes.get_dword(buffer_addr+i*12)).name] = Conf_header_t(buffer_addr+i*12)
        self.encrypted_buff = ida_bytes.get_bytes(buffer_addr + entry_count*12, size)
        self.data = {}
        for i in range(len(CONFIG_INDEX_ENUM)):
            config_name = CONFIG_INDEX_ENUM(i).name
            if config_name in self.header:
                cypher = AES.new(AES_key, AES.MODE_CBC, bytes(16))
                encrypted_data_size = AES.block_size * ((self.header[config_name].size // AES.block_size) +1)
                self.data[config_name] = cypher.decrypt(self.encrypted_buff[self.header[config_name].offset:][:encrypted_data_size])[:self.header[config_name].size]
                if self.data[config_name][1] == 0:
                    self.data[config_name] = self.data[config_name].decode('utf-16').encode('utf-8')
 
 
    def __str__(self):
        return_string = "\tCONF:\n"
        return_string += f"\t\t entry count:  {hex(self.entry_count)}\n"
        for i in range(len(CONFIG_INDEX_ENUM)):
            config_name = CONFIG_INDEX_ENUM(i).name
            if config_name in self.header:
                if "HASH" in config_name or "RSA" in config_name or "FLAG" in config_name:
                    return_string += f"\t\t {config_name}:  {self.data[config_name].hex()}\n"
                elif "SIZE" in config_name:
                    return_string += f"\t\t {config_name}:  {int.from_bytes(self.data[config_name], 'big')} bytes\n"
                elif len(self.data[config_name]) > 1000:
                    return_string += f"\t\t {config_name} (size too big, showing only first 100):  {self.data[config_name][:100]}\n"
                else:
                    return_string += f"\t\t {config_name}:  {self.data[config_name]}\n"
            else:
                print(f"{config_name} not in conf")
        return return_string
        
class Phobos_payload_t:
    def __init__(self, header_name):
         self.header = Payload_header_t(header_name)
         self.entry_count = ida_bytes.get_dword(self.header.payload_addr)
         self.encrypted_buff_size = ida_bytes.get_dword(self.header.payload_addr+4)
         self.conf = Phobos_conf_t(self.header.payload_addr+8, self.encrypted_buff_size, self.entry_count, self.header.AES_key)
 
    def __str__(self):
        return_string = "PAYLOAD:\n"
        return_string += str(self.header)
        return_string += str(self.conf)
        return return_string
        
Phobos_payload = Phobos_payload_t("payload_header")
 
print(Phobos_payload)
