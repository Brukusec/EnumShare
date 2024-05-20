import argparse
import os
import fnmatch
import io
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs
from impacket.examples.smbclient import MiniImpacketShell
from colorama import Fore, Style, init

# Initialize colorama
init()

def listSharesViaSMBConnection(smb_connection):
    shares_info = []
    try:
        rpctransport = transport.SMBTransport(smb_connection.getRemoteName(), smb_connection.getRemoteHost(), filename=r'\srvsvc', smb_connection=smb_connection)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        resp = srvs.hNetrShareEnum(dce, 1)
        shares_list = resp['InfoStruct']['ShareInfo']['Level1']['Buffer']

        for share in shares_list:
            share_name = share['shi1_netname'][:-1]
            remark = share['shi1_remark'] if share['shi1_remark'] else ""
            read_perm = checkShareReadPermission(smb_connection, share_name)
            write_perm = checkShareWritePermission(smb_connection, share_name)
            permission = 'Read/Write' if read_perm and write_perm else 'Read' if read_perm else 'Write' if write_perm else 'None'
            shares_info.append((share_name, permission, remark))

        return shares_info

    except Exception as e:
        if 'STATUS_ACCESS_DENIED' not in str(e):
            print(f"Failed to list shares: {e}")
        return []

def checkShareReadPermission(smb_connection, share_name):
    try:
        smb_connection.listPath(share_name, '*')
        return True
    except Exception:
        return False

def checkShareWritePermission(smb_connection, share_name):
    try:
        treeId = smb_connection.connectTree(share_name)
        fileId = smb_connection.createFile(treeId, "\\test.txt",
                                           desiredAccess=0x02000000,  # GENERIC_ALL
                                           shareMode=0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                                           creationOption=0x00000040,  # FILE_NON_DIRECTORY_FILE
                                           creationDisposition=0x00000005,  # FILE_OVERWRITE_IF
                                           fileAttributes=0x00000080,  # FILE_ATTRIBUTE_NORMAL
                                           impersonationLevel=0x00000002,  # SecurityImpersonation
                                           securityFlags=0,
                                           oplockLevel=0x00,  # SMB2_OPLOCK_LEVEL_NONE
                                           createContexts=None)

        smb_connection.closeFile(treeId, fileId)
        smb_connection.deleteFile(share_name, "\\test.txt")
        return True
    except Exception:
        return False

def getBasicServerInfo(smb_connection):
    try:
        server_name = smb_connection.getServerName()
        domain_name = smb_connection.getServerDomain()
        server_os = smb_connection.getServerOS()
        return {
            'server_name': server_name,
            'domain_name': domain_name,
            'server_os': server_os
        }
    except Exception as e:
        print(f"Failed to retrieve basic server info: {e}")
        return {
            'server_name': 'N/A',
            'domain_name': 'N/A',
            'server_os': 'N/A'
        }

def connect_and_list_shares(remote_host, username, password, domain=''):
    smb_connection = SMBConnection(remoteName=remote_host, remoteHost=remote_host)
    try:
        smb_connection.login(user=username, password=password, domain=domain)
        server_info = getBasicServerInfo(smb_connection)
        shares_info = listSharesViaSMBConnection(smb_connection)
        return server_info, shares_info
    except Exception as e:
        print(f"Failed to connect to {remote_host}: {e}")
        return {}, []
    finally:
        smb_connection.logoff()

class CustomSMBShell(MiniImpacketShell):
    def __init__(self, smbClient, server_ip):
        super().__init__(smbClient)
        self.search_patterns = []
        self.search_strings = []
        self.server_ip = server_ip

    def do_help(self, line):
        print(Fore.CYAN + "Interactive SMB Client" + Style.RESET_ALL)
        print(Fore.CYAN + "=====================" + Style.RESET_ALL)
        print(Fore.CYAN + "Available commands:" + Style.RESET_ALL)
        print(Fore.CYAN + "  shares                 - List available shares" + Style.RESET_ALL)
        print(Fore.CYAN + "  use {sharename}        - Connect to a specific share" + Style.RESET_ALL)
        print(Fore.CYAN + "  cd {path}              - Change the current directory to {path}" + Style.RESET_ALL)
        print(Fore.CYAN + "  lcd {path}             - Change the current local directory to {path}" + Style.RESET_ALL)
        print(Fore.CYAN + "  pwd                    - Show the current remote directory" + Style.RESET_ALL)
        print(Fore.CYAN + "  password               - Change the user password, the new password will be prompted for input" + Style.RESET_ALL)
        print(Fore.CYAN + "  ls {wildcard}          - List all the files in the current directory" + Style.RESET_ALL)
        print(Fore.CYAN + "  lls {dirname}          - List all the files on the local filesystem" + Style.RESET_ALL)
        print(Fore.CYAN + "  tree {filepath}        - Recursively list all files in folder and subfolders" + Style.RESET_ALL)
        print(Fore.CYAN + "  rm {file}              - Remove the selected file" + Style.RESET_ALL)
        print(Fore.CYAN + "  mkdir {dirname}        - Create the directory under the current path" + Style.RESET_ALL)
        print(Fore.CYAN + "  rmdir {dirname}        - Remove the directory under the current path" + Style.RESET_ALL)
        print(Fore.CYAN + "  put {filename}         - Upload the filename into the current path" + Style.RESET_ALL)
        print(Fore.CYAN + "  get {filename}         - Download the filename from the current path" + Style.RESET_ALL)
        print(Fore.CYAN + "  mget {mask}            - Download all files from the current directory matching the provided mask" + Style.RESET_ALL)
        print(Fore.CYAN + "  cat {filename}         - Read the filename from the current path" + Style.RESET_ALL)
        print(Fore.CYAN + "  list_snapshots {path}  - List the VSS snapshots for the specified path" + Style.RESET_ALL)
        print(Fore.CYAN + "  info                   - Return NetrServerInfo main results" + Style.RESET_ALL)
        print(Fore.CYAN + "  search <pattern1> <pattern2> ... [-s <string1 string2 ...>]" + Style.RESET_ALL)
        print(Fore.CYAN + "                          Search for files matching the patterns" + Style.RESET_ALL)
        print(Fore.CYAN + "                          Optionally, search for strings inside those files" + Style.RESET_ALL)
        print(Fore.CYAN + "                          Example: search *.txt *.bat -s string1 string2" + Style.RESET_ALL)
        print(Fore.CYAN + "  close                  - Close the current SMB session")
        print(Fore.CYAN + "  exit                   - Terminate the server process (and this session)")



    def do_search(self, line):
        "Search for files matching the given patterns in the current directory and all its subdirectories. Optionally, search for strings inside those files."
        if not self.share:
            print("No share selected. Use 'cd <share_name>' to select a share.")
            return
        if not line:
            print("Usage: search <pattern1> <pattern2> ... [-s <string1 string2 ...>]")
            return

        args = line.split(' ')
        patterns = []
        search_strings = []
        in_search_mode = False

        for arg in args:
            if arg == '-s':
                in_search_mode = True
                continue
            if in_search_mode:
                search_strings.append(arg.strip())
            else:
                patterns.append(arg.strip())

        self.search_patterns = patterns
        self.search_strings = search_strings

        search_info = f"Searching files with patterns '{', '.join(self.search_patterns)}'"
        if self.search_strings:
            search_info += f" and containing the text(s) '{', '.join(self.search_strings)}'"
        print(Fore.BLUE + search_info + Style.RESET_ALL)

        self.search_files(self.share, self.pwd)

    def search_files(self, share, directory):
        try:
            path = f"{directory}\\" if directory else ""
            files = self.smb.listPath(share, f"\\{path}*")
            for f in files:
                if f.is_directory() and f.get_longname() not in ['.', '..']:
                    self.search_files(share, f"{directory}\\{f.get_longname()}")
                else:
                    for pattern in self.search_patterns:
                        if fnmatch.fnmatch(f.get_longname(), pattern):
                            share = str(share)
                            path = str(path)
                            file_name = str(f.get_longname())

                            # Formar o caminho completo do SMB
                            file_path = f"\\{share}\\{path}{file_name}"
                            print(Fore.BLUE + f"Attempting to read file: {file_name} in {path}" + Style.RESET_ALL)
                            if self.search_strings:
                                self.search_in_file(share, path, file_name)
                            break
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' not in str(e):
                print(f"Failed to search in {directory}: {e}")

    def search_in_file(self, share, path, file_name):
        try:
            buffer = io.BytesIO()
            self.smb.getFile(share, f"{path}\\{file_name}", buffer.write)
            buffer.seek(0)
            file_data = buffer.getvalue()

            if file_data:
                print("File read successfully")
                lines = file_data.decode(errors='ignore').splitlines()
                for search_str in self.search_strings:
                    for i, line in enumerate(lines):
                        if search_str in line:
                            print(Fore.GREEN + f"Line {i + 1} - {line.strip()}" + Style.RESET_ALL)

        except Exception as e:
            print(f"Failed to read file {file_name} in {path}: {e}")

def smbclient_interactive(remote_host, username, password, domain):
    try:
        print(f"[+] Connecting to {remote_host}...")
        smb_connection = SMBConnection(remoteName=remote_host, remoteHost=remote_host)
        smb_connection.login(username, password, domain)
        print("[+] Login successful")

        shell = CustomSMBShell(smb_connection, remote_host)
        shell.cmdloop()
    except Exception as e:
        print(f"[-] Failed to connect or login: {e}")

def process_host(host, username, password, domain, client_mode):
    if client_mode:
        smbclient_interactive(host, username, password, domain)
    else:
        server_info, shares_info = connect_and_list_shares(host, username, password, domain)
        if server_info:
            print(f"ServerName - {server_info['server_name']} - IP address: {host}")
            print(f"Windows Server Version: {server_info['server_os']}")
        else:
            print("Failed to retrieve server info.")

        print(f"Domain name: {domain if domain else 'N/A'}")
        print(f"Username used: {username}")
        print("\nEnumerated shares:\n")
        print(f"{'Share':<25} | {'Permission':<12} | {'Remark'}")
        print("-" * 60)
        for share_name, permission, remark in shares_info:
            print(f"{share_name:<25} | {permission:<12} | {remark}")
        print("\n" + "="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Enumerate SMB shares on a remote host and check permissions or use SMB client mode.')
    parser.add_argument('-H', '--hosts', required=True, help='Remote host IP or hostname, or file containing a list of hosts')
    parser.add_argument('-u', '--username', required=True, help='Username for SMB authentication')
    parser.add_argument('-p', '--password', required=True, help='Password for SMB authentication')
    parser.add_argument('-d', '--domain', default='', help='Domain for SMB authentication (optional)')
    parser.add_argument('-c', '--client', action='store_true', help='Use SMB client mode')

    args = parser.parse_args()

    hosts = []
    if os.path.isfile(args.hosts):
            hosts = [line.strip() for line in file if line.strip()]
    else:
        hosts = [args.hosts]

    for host in hosts:
        print(f"Processing host: {host}")
        process_host(host, args.username, args.password, args.domain, args.client)

if __name__ == '__main__':
    main()

