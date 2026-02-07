ALLOWED_COMMANDS = {
    "ls", "pwd", "cat", "file", "grep", "awk", "sed",
    "whoami", "id", "uname",
    "strings", "xxd", "hexdump",
    "python3", "pip"
}

DANGEROUS_TOKENS = {
    ";", "|", "&&", "||", ">", ">>",
    "--no-preserve-root", "-rf"
}
