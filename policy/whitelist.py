ALLOWED_COMMANDS = {
    # Filesystem
    "ls", "pwd", "cat", "file", "find", "locate", "tree",
    "cp", "mv", "mkdir", "touch", "rm", "chmod", "chown",
    # Text processing
    "grep", "awk", "sed", "cut", "sort", "uniq", "wc", "head", "tail",
    "diff", "tr", "echo",
    # System info
    "whoami", "id", "uname", "uptime", "df", "du", "free", "lscpu",
    "env", "printenv", "date", "hostname",
    # Process management
    "ps", "top", "kill", "pgrep", "pkill",
    # Networking
    "ping", "curl", "wget", "nmap", "netstat", "ss", "ip",
    "dig", "nslookup", "traceroute", "whois", "nc",
    # Archives
    "tar", "zip", "unzip", "gzip", "gunzip",
    # Forensics / CTF
    "strings", "xxd", "hexdump", "objdump", "readelf", "ltrace", "strace",
    "binwalk", "exiftool", "file",
    # Dev / scripting
    "python3", "python", "pip", "pip3",
    "gcc", "g++", "make", "git",
}

DANGEROUS_TOKENS = {
    # Pipes/redirects are now allowed so chaining whitelist-safe cmds works.
    # We still block the most destructive flags/patterns.
    "--no-preserve-root",
    "-rf",
    "--delete",
    # Prevent writing to arbitrary files via redirection (agent shouldn't need this)
    ">", ">>",
}
