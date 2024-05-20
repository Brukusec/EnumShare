# SMB Enumeration and Interactive Shell Script

This Python script is designed to enumerate SMB shares on remote hosts, check permissions, and provide an interactive SMB client shell for further operations. The script leverages the Impacket library to perform these tasks and includes additional functionality for searching files and strings within those files on SMB shares.

## Features

- Enumerate SMB shares and check read/write permissions.
- Retrieve basic server information.
- Interactive SMB client shell with various commands.
- Search for files matching multiple patterns and strings within those files.

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Brukusec/EnumShare.git
   cd smb_enum_shell

2. **Install the required dependencies:**
   ```sh
   pip install -r requirements.txt

## Usage
### Enumerate SMB Shares
To enumerate SMB shares on a remote host, use the following command:

    python smb_enum.py -H <host> -u <username> -p <password> -d <domain>

### Interactive SMB Client Shell
To start the interactive SMB client shell, use the -c option:

    python smb_enum.py -H <host> -u <username> -p <password> -d <domain> -c

### Parameters

- -H, --hosts: Remote host IP or hostname, or file containing a list of hosts.
- -u, --username: Username for SMB authentication.
- -p, --password: Password for SMB authentication.
- -d, --domain: Domain for SMB authentication (optional).
- -c, --client: Use SMB client mode.

### Interactive Shell Commands

- shares: List available shares.
- use {sharename}: Connect to a specific share.
- cd {path}: Change the current directory to {path}.
- lcd {path}: Change the current local directory to {path}.
- pwd: Show the current remote directory.
- ls {wildcard}: List all the files in the current directory.
- lls {dirname}: List all the files on the local filesystem.
- tree {filepath}: Recursively list all files in folder and subfolders.
- rm {file}: Remove the selected file.
- mkdir {dirname}: Create the directory under the current path.
- rmdir {dirname}: Remove the directory under the current path.
- put {filename}: Upload the filename into the current path.
- get {filename}: Download the filename from the current path.
- mget {mask}: Download all files from the current directory matching the provided mask.
- cat {filename}: Read the filename from the current path.
- list_snapshots {path}: List the VSS snapshots for the specified path.
- info: Return NetrServerInfo main results.
- close: Close the current SMB session.
- exit: Terminate the server process (and this session).
- search <pattern1> <pattern2> ... [-s <string1 string2 ...>]: Search for files matching the patterns and optionally search for strings inside those files.

### Example

To search for .bat and .txt files containing the string "example" on a remote host:

     search *.bat *.txt -s example

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
