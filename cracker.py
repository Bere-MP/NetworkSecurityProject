import hashlib
from multiprocessing import Pool, cpu_count, Manager

# Set up the files
passwordFile = "passwords.txt"
dictionaryFile = "dictionary.txt"

# Output the cracked passwords found within the program
outputFile = "cracked.txt"

# Brute Force Numbers
maxDigitLength = 10
# Maximum amount of digits at the end of words
maxEndDigits = 5
# Amount of double words
multiWordProcessingLimit = 3000

# How many workers processes
workers = max(1, cpu_count() - 1)

# Tracking the cracked passwords
cracked_all = {}       # hash -> plaintext
# Tracks how many found within each stage
cracked_by_stage = {1:{},2:{},3:{},4:{}}

# Computes SHA-1 hex of a given string
def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest()
# Reference:
# - https://docs.python.org/3/library/hashlib.html
# - https://www.geeksforgeeks.org/python/hashlib-module-in-python/


# Loads all the passwords into a set
def load_passwords(filename):
    passwordInfo = {}
    # Open the password file to strip both the User ID and the SHA-1 Hash
    with open(filename,"r",encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()

            # Ensures the line within the file contains two values
            if len(parts)>=2:
                passwordInfo[parts[0]] = parts[1].lower()
    return passwordInfo, set(passwordInfo.values())

# Loads all the words from the dictionary file into a list
def load_dictionary(filename):
    wordInfo=[]

    # Opens the dictionary text file to get words
    with open(filename,"r",encoding="utf-8") as f:
        for line in f:
            w=line.strip().lower()
            if w: wordInfo.append(w)
    return wordInfo

# Compute hash function to our hash set
def check_tuple(args):
    cand, hashset = args
    h = sha1_hex(cand)
    # If what was computed was also found in the hashset, return password
    if h in hashset:
        return (h, cand)
    return None

# Saves all the cracked passwords put into its own file
def save_cracked_passwords(map_uid_plain):
    with open(outputFile,"w",encoding="utf-8") as f:
        for uid,plain in map_uid_plain.items():
            # Write file in the format: (User ID) (PlainText: SHA-1 Hash)
            f.write(f"{uid} {plain}\n")
            # This allows for us to know what passwords were cracked and which weren't


# Main program
def main():
    # Set out and read the password and dictionary file
    pw_map, target_hashes = load_passwords(passwordFile)
    words = load_dictionary(dictionaryFile)

    # Read the amount of lines within the file (size)
    print(f"Loaded {len(pw_map)} entries.")
    print(f"Loaded {len(words)} dictionary words.")

    # Create shared processes and data found
    manager = Manager()
    cracked_uid = manager.dict()      # userId → plaintext
    found_hashes = manager.dict()     # hash → True

    # Registers a match within each stage
    def register_match(h, candidate, stage):
        # Record hit (Locally: stage)
        cracked_by_stage[stage][h] = candidate

        # Check if hit was found within other stages
        if h not in cracked_all:
            cracked_all[h] = candidate

        # Output if hit was found
        for uid, hh in pw_map.items():
            if hh == h and uid not in cracked_uid:
                cracked_uid[uid] = candidate
                found_hashes[h] = True
                print(f"[FOUND] uid={uid} hash={h}  pass='{candidate}'")

    # Stage 1 — dictionary attack
    print("\nStage 1: Dictionary Words")
    stage = 1

    def pc_stage1():
        for w in words:
            yield (w, target_hashes)  # words within the dictionary file

    # Improve Performance by limiting the amount to the pool
    # Workers do the job of processing stage and comparing output
    with Pool(workers) as p:
        for res in p.imap_unordered(check_tuple, pc_stage1(), chunksize=250): # Limit amount of words within process
            if res:
                h, c = res
                # register a match within the program if found
                register_match(h, c, stage)
    # Reference:
    # - Google Prompt: Dictionary Attack Python
    # - https://www.paloaltonetworks.com/cyberpedia/dictionary-attack
    # - https://www.w3resource.com/python-exercises/cybersecurity/python-cybersecurity-exercise-9.php

    # Stage 2 — dictionary + numbers
    print("\nStage 2: Dictionary + Numbers ")
    stage = 2

    def pc_stage2():
        # Total number of possible combinations along with the limitations of this stage
        width = maxEndDigits
        maxn = 10 ** maxEndDigits
        for w in words:
            # dictionary words
            yield (w, target_hashes)

            for n in range(maxn):
                # zero-padded version
                yield (w + str(n).zfill(width), target_hashes)

                # non-padded version
                yield (w + str(n), target_hashes)

    # Workers do the job of processing stage and comparing output
    with Pool(workers) as p:
        for res in p.imap_unordered(check_tuple, pc_stage2(), chunksize=500):
            if res:
                h,c = res
                register_match(h,c,stage)
    # Reference:
    # - https://medium.com/@rdillon73/hacktrick-building-a-dictionary-tool-in-python-to-pentest-those-who-went-bananas-ddaf4fc94f24

    # Stage 3 — Numbers Brute Force
    print("\nStage 3: Numbers Brute Force")
    stage = 3

    # Attempts to crack the password through just numerical sequence
    with Pool(workers) as p:
        # L = length of sequence (ex: L = 3 -> 000, 001, 002, etc.)
        for L in range(1, maxDigitLength+1):
            def pc_stage3():
                for n in range(10**L):
                    yield (str(n).zfill(L), target_hashes)

            # Workers do the job of processing stage and comparing output
            for res in p.imap_unordered(check_tuple, pc_stage3(), chunksize=1000):
                if res:
                    h,c = res
                    register_match(h,c,stage)

    # Reference:
    # - https://www.mdpi.com/2076-3417/13/10/5979
    # - https://youtu.be/P5Lt8J3_ZnI?si=1CyH573m24bArOmU

    # Stage 4 — Multi Word Combos
    print("\nStage 4: Multi-Words (2 - 4 Words)")
    stage = 4

    # Limit the amound of words from the dictionary file
    # Avoids reduction in performance
    subset = words[:multiWordProcessingLimit]

    def pc_stage4():

        # 2-words
        for a in subset:
            for b in subset:
                yield (a + b, target_hashes)

        # 3-words
        for a in subset:
            for b in subset:
                for c in subset:
                    yield (a + b + c, target_hashes)

        # 4-words
        for a in subset:
            for b in subset:
                for c in subset:
                    for d in subset:
                        yield (a + b + c + d, target_hashes)

    with Pool(workers) as p:
        for res in p.imap_unordered(check_tuple, pc_stage4(), chunksize=500):
            if res:
                h, c = res
                register_match(h, c, stage)
    # Reference:
    # - Google Prompt: Dictionary Attack Python
    # - https://www.paloaltonetworks.com/cyberpedia/dictionary-attack
    # - https://www.w3resource.com/python-exercises/cybersecurity/python-cybersecurity-exercise-9.php


    # Print Results
    print("\nComplete.")
    print(f"Total cracked accounts: {len(cracked_uid)}")

    print(f"Total cracked passwords: {len(cracked_by_stage)}")
    save_cracked_passwords(dict(cracked_uid))

    # Create output file with the cracked passwords
    print("Wrote cracked.txt")

    # Find how many were found within each stage
    print("\nPer-stage results:")
    for s in range(1,5):
        print(f"  Stage {s}: {len(cracked_by_stage[s])}")
        # change functions base on what was found

if __name__ == "__main__":
    main()

# References:
# - https://www.ibm.com/think/x-force/how-not-to-store-passwords-sha-1-fails-again
# - https://www.mdpi.com/2076-3417/13/10/5979