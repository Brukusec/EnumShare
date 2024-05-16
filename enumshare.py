import argparse
import os
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs

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

def smbclient(remote_host, username, password, domain):
    smb_connection = SMBConnection(remoteName=remote_host, remoteHost=remote_host)
    smb_connection.login(user=username, password=password, domain=domain)

    current_share = None
    while True:
        command = input("SMBClient> ").strip().split()
        if not command:
            continue
        cmd = command[0].lower()

        if cmd == 'exit':
            break
        elif cmd == 'help':
            print_help()
        elif cmd == 'list':
            shares = smb_connection.listShares()
            for share in shares:
                print(f"{share['shi1_netname'][:-1]} - {share['shi1_remark']}")
        elif cmd == 'cd':
            if len(command) < 2:
                print("Usage: cd <share_name>")
            else:
                current_share = command[1]
                print(f"Current share: {current_share}")
        elif cmd == 'ls':
            if not current_share:
                print("No share selected. Use 'cd <share_name>' to select a share.")
            else:
                try:
                    files = smb_connection.listPath(current_share, '*')
                    for file in files:
                        print(f"{file.get_longname()} - {file.get_filesize()} bytes")
                except Exception as e:
                    print(f"Failed to list directory: {e}")
        elif cmd == 'download':
            if len(command) < 3:
                print("Usage: download <remote_path> <local_path>")
            else:
                remote_path = command[1]
                local_path = command[2]
                try:
                    with open(local_path, 'wb') as f:
                        smb_connection.getFile(current_share, remote_path, f.write)
                    print(f"Downloaded {remote_path} to {local_path}")
                except Exception as e:
                    print(f"Failed to download file: {e}")
        elif cmd == 'upload':
            if len(command) < 3:
                print("Usage: upload <local_path> <remote_path>")
            else:
                local_path = command[1]
                remote_path = command[2]
                try:
                    with open(local_path, 'rb') as f:
                        smb_connection.putFile(current_share, remote_path, f.read)
                    print(f"Uploaded {local_path} to {remote_path}")
                except Exception as e:
                    print(f"Failed to upload file: {e}")
        else:
            print("Unknown command. Type 'help' for a list of commands.")

def print_help():
    print("""
Available commands:
  list                 List shares on the server
  cd <share_name>      Change to the specified share
  ls                   List directories and files in the current share
  download <remote_path> <local_path>  Download a file from the share
  upload <local_path> <remote_path>  Upload a file to the share
  help                 Display this help message
  exit                 Exit the SMB client
""")

def process_host(host, username, password, domain, client_mode):
    if client_mode:
        smbclient(host, username, password, domain)
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
        with open(args.hosts, 'r') as file:
            hosts = [line.strip() for line in file if line.strip()]
    else:
        hosts = [args.hosts]

    for host in hosts:
        print(f"Processing host: {host}")
        process_host(host, args.username, args.password, args.domain, args.client)

if __name__ == '__main__':
    main()
