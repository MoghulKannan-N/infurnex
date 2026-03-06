# infurnex/flag_detector.py
import re # regex library for pattern matching
from typing import Optional # type hinting for nullable returns
import logging # structured logging system

# Output format for stdout
logging.basicConfig(level=logging.INFO, format='%(asctime)s - DETECTOR - %(message)s')

def detect_flag(response_text: str) -> bool:
    # Boolean check if any known CTF flag format exists in the text buffer
    # Standard formats map to major platforms
    patterns = [
        r"picoCTF\{[^}]+\}", # picoCTF standard format
        r"flag\{[^}]+\}", # Generic CTF format
        r"HTB\{[^}]+\}", # HackTheBox format
        r"CTF\{[^}]+\}" # Alternative generic format
    ]
    
    for pattern in patterns: # iterate regex rules
        if re.search(pattern, response_text): # if a match is mathematically found
            return True # exit early with positive confirmation
            
    return False # return negative if loop completes

def extract_flag(response_text: str) -> Optional[str]:
    # Extracts the exact string matching a flag format
    # Similar rules engine to the detection phase
    patterns = [
        r"picoCTF\{[^}]+\}", # picoCTF standard format
        r"flag\{[^}]+\}", # Generic CTF format
        r"HTB\{[^}]+\}", # HackTheBox format 
        r"CTF\{[^}]+\}" # Alternative generic format
    ]
    
    for pattern in patterns: # iterate string extraction rules
        matches = re.findall(pattern, response_text) # dump all matches to array
        if matches: # check array truthiness
            extracted = matches[0] # isolate the first match found
            logging.critical(f"FLAG IDENTIFIED: {extracted}") # emit critical logic visual
            return extracted # return string 
            
    # if execution reaches here, no flag was found
    return None # return null string reference
