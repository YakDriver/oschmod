# -*- coding: utf-8 -*-
"""winlxchmod module.

Module for working with file permissions.

These bitwise permissions from the stat module can be used with this module:
    stat.S_IRWXU   # Mask for file owner permissions
    stat.S_IREAD   # Owner has read permission
    stat.S_IRUSR   # Owner has read permission
    stat.S_IWRITE  # Owner has write permission
    stat.S_IWUSR   # Owner has write permission
    stat.S_IEXEC   # Owner has execute permission
    stat.S_IXUSR   # Owner has execute permission

    stat.S_IRWXG   # Mask for group permissions
    stat.S_IRGRP   # Group has read permission
    stat.S_IWGRP   # Group has write permission
    stat.S_IXGRP   # Group has execute permission

    stat.S_IRWXO   # Mask for permissions for others (not in group)
    stat.S_IROTH   # Others have read permission
    stat.S_IWOTH   # Others have write permission
    stat.S_IXOTH   # Others have execute permission

"""

import os
import random
import stat
import string


HAS_PYWIN32 = False
try:
    import ntsecuritycon  # noqa: F401
    import win32security  # noqa: F401
    HAS_PYWIN32 = True
except ImportError:
    pass

WIN_FILE_ACCESS = []
WIN_DIR_ACCESS = []
if HAS_PYWIN32:
    WIN_FILE_ACCESS = [
        0,
        ntsecuritycon.FILE_GENERIC_EXECUTE,
        ntsecuritycon.FILE_GENERIC_WRITE,
        (
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_GENERIC_WRITE |
            ntsecuritycon.FILE_GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_GENERIC_READ
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_GENERIC_READ |
            ntsecuritycon.FILE_GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_GENERIC_READ |
            ntsecuritycon.FILE_GENERIC_WRITE
        ),
        ntsecuritycon.FILE_ALL_ACCESS
    ]

    WIN_DIR_ACCESS = [
        0,
        (
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_WRITE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_WRITE |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.GENERIC_READ
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_WRITE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_WRITE |
            ntsecuritycon.GENERIC_EXECUTE |
            ntsecuritycon.GENERIC_ALL
        )
    ]


W_FLDIR = ntsecuritycon.FILE_LIST_DIRECTORY    # =                           1
W_FADFL = ntsecuritycon.FILE_ADD_FILE          # =                          10
W_FADSD = ntsecuritycon.FILE_ADD_SUBDIRECTORY  # =                         100
W_FRDEA = ntsecuritycon.FILE_READ_EA           # =                        1000
W_FWREA = ntsecuritycon.FILE_WRITE_EA          # =                       10000
W_FTRAV = ntsecuritycon.FILE_TRAVERSE          # =                      100000
W_FDLCH = ntsecuritycon.FILE_DELETE_CHILD      # =                     1000000
W_FRDAT = ntsecuritycon.FILE_READ_ATTRIBUTES   # =                    10000000
W_FWRAT = ntsecuritycon.FILE_WRITE_ATTRIBUTES  # =                   100000000
W_DELET = ntsecuritycon.DELETE                 # =           10000000000000000
W_RDCON = ntsecuritycon.READ_CONTROL           # =          100000000000000000
W_WRDAC = ntsecuritycon.WRITE_DAC              # =         1000000000000000000
W_WROWN = ntsecuritycon.WRITE_OWNER            # =        10000000000000000000
W_SYNCH = ntsecuritycon.SYNCHRONIZE            # =       100000000000000000000
W_FGNEX = ntsecuritycon.FILE_GENERIC_EXECUTE   # =       100100000000010100000
W_FGNRD = ntsecuritycon.FILE_GENERIC_READ      # =       100100000000010001001
W_FGNWR = ntsecuritycon.FILE_GENERIC_WRITE     # =       100100000000100010110
W_GENAL = ntsecuritycon.GENERIC_ALL            # 10000000000000000000000000000
W_GENEX = ntsecuritycon.GENERIC_EXECUTE       # 100000000000000000000000000000
W_GENWR = ntsecuritycon.GENERIC_WRITE        # 1000000000000000000000000000000
W_GENRD = ntsecuritycon.GENERIC_READ       # -10000000000000000000000000000000

W_DIRRD = W_FLDIR | W_FRDEA | W_FRDAT | W_RDCON | W_SYNCH
W_DIRWR = W_FADFL | W_FADSD | W_FWREA | W_FDLCH | W_FWRAT | W_DELET | W_RDCON \
    | W_WRDAC | W_WROWN | W_SYNCH
W_DIREX = W_FTRAV | W_RDCON | W_SYNCH

W_FILRD = W_FGNRD
W_FILWR = W_FDLCH | W_DELET | W_WRDAC | W_WROWN | W_FGNWR
W_FILEX = W_FGNEX

FILE = 0
DIRECTORY = 1

OBJECT_TYPES = [FILE, DIRECTORY]

OWNER = 0
GROUP = 1
OTHER = 2

OWNER_TYPES = [OWNER, GROUP, OTHER]

READ = 0
WRITE = 1
EXECUTE = 2

OPER_TYPES = [READ, WRITE, EXECUTE]

STAT_MASKS = [
    [stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR],
    [stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP],
    [stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH]
]

STAT_KEYS = (
    "S_IRUSR",
    "S_IWUSR",
    "S_IXUSR",
    "S_IRGRP",
    "S_IWGRP",
    "S_IXGRP",
    "S_IROTH",
    "S_IWOTH",
    "S_IXOTH"
)

WIN_RWX_PERMS = [
    [W_FILRD, W_FILWR, W_FILEX],
    [W_DIRRD, W_DIRWR, W_DIREX]
]


__version__ = "0.1.0"


def win_get_owner_sid(path):
    """Get the file owner."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorOwner()
    return sid


def win_get_group_sid(path):
    """Get the file group."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.GROUP_SECURITY_INFORMATION)
    return sec_descriptor.GetSecurityDescriptorGroup()


def win_get_other_sid():
    """Get the other SID.

    For now this is the Users builtin account. In the future, probably should
    allow account to be passed in and find any non-owner, non-group account
    currently associated with the file. As a default, it could use Users."""
    return win32security.LookupAccountName(None, 'Users')[0]


def win_get_permissions(path):
    """Set the file or dir permissions."""
    if not os.path.exists(path):
        raise FileNotFoundError('Path %s could not be found.' % path)

    _win_get_permissions(path)


def _win_get_permissions(path):
    """Get the permissions."""
    # if os.path.isfile(path):
    #     accesses = WIN_FILE_ACCESS
    # else:
    #    accesses = WIN_DIR_ACCESS

    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()

    owner_sid = win_get_owner_sid(path)
    group_sid = win_get_group_sid(path)

    perm = 0
    for index in range(0, dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if ace[2] == owner_sid:
            if ace[1] & ntsecuritycon.FILE_GENERIC_READ == \
                    ntsecuritycon.FILE_GENERIC_READ:
                perm = perm | stat.S_IRUSR
            if ace[1] & ntsecuritycon.FILE_GENERIC_WRITE == \
                    ntsecuritycon.FILE_GENERIC_WRITE:
                perm = perm | stat.S_IWUSR
            if ace[1] & ntsecuritycon.FILE_GENERIC_EXECUTE == \
                    ntsecuritycon.FILE_GENERIC_EXECUTE:
                perm = perm | stat.S_IXUSR
        elif ace[2] == group_sid:
            if ace[1] & ntsecuritycon.FILE_GENERIC_READ == \
                    ntsecuritycon.FILE_GENERIC_READ:
                perm = perm | stat.S_IRGRP
            if ace[1] & ntsecuritycon.FILE_GENERIC_WRITE == \
                    ntsecuritycon.FILE_GENERIC_WRITE:
                perm = perm | stat.S_IWGRP
            if ace[1] & ntsecuritycon.FILE_GENERIC_EXECUTE == \
                    ntsecuritycon.FILE_GENERIC_EXECUTE:
                perm = perm | stat.S_IXGRP
        elif win32security.LookupAccountSid(None, ace[2])[0] != 'SYSTEM':
            if ace[1] & ntsecuritycon.FILE_GENERIC_READ == \
                    ntsecuritycon.FILE_GENERIC_READ:
                perm = perm | stat.S_IROTH
            if ace[1] & ntsecuritycon.FILE_GENERIC_WRITE == \
                    ntsecuritycon.FILE_GENERIC_WRITE:
                perm = perm | stat.S_IWOTH
            if ace[1] & ntsecuritycon.FILE_GENERIC_EXECUTE == \
                    ntsecuritycon.FILE_GENERIC_EXECUTE:
                perm = perm | stat.S_IXOTH

    print("Mode: ", perm, "hex:", hex(perm))
    return perm


def win_set_permissions(path, mode):
    """Set the file or dir permissions."""
    if not os.path.exists(path):
        raise FileNotFoundError('Path %s could not be found.' % path)

    object_type = DIRECTORY
    if os.path.isfile(path):
        object_type = FILE

    return _win_set_permissions(path, mode, object_type)


def _win_get_accesses(mode, user_type, object_type):
    """Get bitwise permissions for user type."""
    access = 0

    for oper in OPER_TYPES:
        if mode & STAT_MASKS[user_type][oper] == STAT_MASKS[user_type][oper]:
            access = access | WIN_RWX_PERMS[object_type][oper]

    return access


def _win_set_permissions(path, mode, object_type):
    """Set the permissions."""
    # Overview of Windows inheritance:
    # Get/SetNamedSecurityInfo  = Always includes inheritance
    # Get/SetFileSecurity       = Can exclude/disable inheritance
    # Here we read effective permissions with GetNamedSecurityInfo, i.e.,
    # including inherited permissions. However, we'll set permissions with
    # SetFileSecurity and NO_INHERITANCE, to disable inheritance.
    sec_des = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_des.GetSecurityDescriptorDacl()

    for _ in range(0, dacl.GetAceCount()):
        dacl.DeleteAce(0)

    sec_des.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(
        path, win32security.DACL_SECURITY_INFORMATION, sec_des)

    sids = [
        win_get_owner_sid(path),
        win_get_group_sid(path),
        win_get_other_sid()
    ]

    for user_type, sid in enumerate(sids):
        access = _win_get_accesses(mode, user_type, object_type)

        if access > 0:
            dacl.AddAccessAllowedAceEx(
                dacl.GetAclRevision(),
                win32security.NO_INHERITANCE, access, sid)

    sec_des.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(
        path, win32security.DACL_SECURITY_INFORMATION, sec_des)


def win_display_permissions(path):
    """Display permissions."""
    if not os.path.exists(path):
        print(path, "does not exist!")
        raise FileNotFoundError('Path %s could not be found.' % path)

    print("----------------------------------------")
    print("FILE:", path)
    print("Perms:", win_get_permissions(path))

    # get owner SID
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.OWNER_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorOwner()
    print("Owner:", win32security.LookupAccountSid(None, sid))

    # get group SID
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.GROUP_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorGroup()
    print("Group:", win32security.LookupAccountSid(None, sid))

    # get ACEs
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        print("No Discretionary ACL")
        return

    for ace_no in range(0, dacl.GetAceCount()):
        ace = dacl.GetAce(ace_no)
        print("ACE", ace_no)

        print("  -Type")
        for i in (
                "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE",
                "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
            if getattr(ntsecuritycon, i) == ace[0][0]:
                print("    ", i)

        print("  -Flags", hex(ace[0][1]))
        if ace[0][1] == win32security.NO_INHERITANCE:
            print("    ", "NO_INHERITANCE")
        else:
            for i in (
                    "OBJECT_INHERIT_ACE", "CONTAINER_INHERIT_ACE",
                    "NO_PROPAGATE_INHERIT_ACE", "INHERIT_ONLY_ACE",
                    "INHERITED_ACE", "SUCCESSFUL_ACCESS_ACE_FLAG",
                    "FAILED_ACCESS_ACE_FLAG"):
                if ace[0][1] & getattr(win32security, i) == getattr(
                        win32security, i):
                    print("    ", i)

        print("  -mask", hex(ace[1]), "(" + str(ace[1]) + ")")

        # files and directories do permissions differently
        permissions_file = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "FILE_GENERIC_READ", "FILE_GENERIC_WRITE",
            "FILE_GENERIC_EXECUTE", "FILE_DELETE_CHILD")
        permissions_dir = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "FILE_ADD_SUBDIRECTORY", "FILE_ADD_FILE",
            "FILE_DELETE_CHILD", "FILE_LIST_DIRECTORY", "FILE_TRAVERSE",
            "FILE_READ_ATTRIBUTES", "FILE_WRITE_ATTRIBUTES", "FILE_READ_EA",
            "FILE_WRITE_EA")
        permissions_dir_inherit = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "GENERIC_READ", "GENERIC_WRITE", "GENERIC_EXECUTE",
            "GENERIC_ALL")
        if os.path.isfile(path):
            permissions = permissions_file
        else:
            permissions = permissions_dir
            # directories have ACE that is inherited by children within them
            if ace[0][1] & ntsecuritycon.OBJECT_INHERIT_ACE == \
               ntsecuritycon.OBJECT_INHERIT_ACE and ace[0][1] & \
               ntsecuritycon.INHERIT_ONLY_ACE == \
               ntsecuritycon.INHERIT_ONLY_ACE:
                permissions = permissions_dir_inherit

        calc_mask = 0  # see if we are printing all of the permissions
        for i in permissions:
            if getattr(ntsecuritycon, i) & ace[1] == getattr(ntsecuritycon, i):
                calc_mask = calc_mask | getattr(ntsecuritycon, i)
                print("    ", i)
        print("  ", "Calculated Check Mask=", hex(calc_mask))
        print("  -SID\n    ", win32security.LookupAccountSid(None, ace[2]))


def win_perm_test(mode=stat.S_IRUSR | stat.S_IWUSR):
    """Creates test file and modifies permissions."""
    path = ''.join(
        random.choice(string.ascii_letters) for i in range(10)) + '.txt'
    file_hdl = open(path, 'w+')
    file_hdl.write("new file")
    file_hdl.close()
    print("Created test file:", path)

    print("BEFORE Permissions:")
    win_display_permissions(path)

    print("Setting permissions:")
    for i in STAT_KEYS:
        if mode & getattr(stat, i) == getattr(stat, i):
            print("    stat.", i)
    win_set_permissions(path, mode)

    print("AFTER Permissions:")
    win_display_permissions(path)
