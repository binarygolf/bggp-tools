import argparse
import base64
import datetime
import readline
import hashlib
from rich import print # pip install rich
from rich import box
from rich.console import Console
from rich.table import Table
import yxd  # pip install yxdump

# TODO:
# - [ ] Add score calculations
# - [ ] Make base64 decoding in parseEntry a little less painful

# CHANGELOG
# - 2025-02-01 - Script cleanup, styling, and initial release
# - 2025-01-31 - Parsing additions by @deepseagirl
# - 2025-01-30 - Base script created 

parser = argparse.ArgumentParser(description='bggp-tool')
parser.add_argument('-b', dest='verify_binary', help='File To Verify (ANY)')
parser.add_argument('-e', dest='verify_entry', help='BGGP Entry File To Verify (.txt)')
parser.add_argument('-c', dest='create_entry', help='Create entry from file (ANY)')
args    = parser.parse_args()

color_title   = "dark_slate_gray2"
color_splash1 = "dark_slate_gray2"
color_splash2 = "dark_slate_gray2"
color_splash3 = "dark_slate_gray2"
color_splash4 = "dark_slate_gray2" 

splash = f"""
[{color_splash1}] █▄▄▄▄▄▄▄▄▄ █▀▀▀▀▀▀ ▄▄ █▀▀▀▀▀▀ ▄▄ ▀▀▀▀▀▀▀▀▀█ [/{color_splash1}]
[{color_splash2}] ▄▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▀▀▀▀▀▀▀▀▀ [/{color_splash2}]
[{color_splash3}] ▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄ ▄          [/{color_splash3}]
[{color_splash4}]      █     █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄▄ [/{color_splash4}]
"""

helpfile = [
    ("c",          "(c)reate a new entry"),
    ("c file.bin", "(c)reate a new entry from (file.bin)"),
    ("e",          "Load (e)ntry from stdin"),
    ("e file.txt", "Load (e)ntry from (file.txt)"),
    ("i",          "Print info about current entry, if any"),
    ("r",          "(r)eset entry"),
    ("s",          "(s)ave data to bggp.bin"),
    ("s file.bin", "(s)ave data to (file.bin)"),
    ("v",          "(v)erify an entry (creates stub)"),
    ("x",          "E(x)it"),
]

# Signatures for processing entries
entrys = [
    ("start"   , "---BEGIN BGGPx---"),
    ("date"    , "Submit Date:"),
    ("chalnum" , "BGGP Challenge Number:"),
    ("author"  , "Author:"),
    ("contact" , "Contact Info (Optional):"),
    ("online"  , "Online Presence (Website/Social Media):"),
    ("type"    , "Target File Type:"),
    ("size"    , "File Size:"),
    ("hash"    , "SHA256 Hash:"),
    ("env"     , "Target Environment (How do we run the file?):"),
    ("info"    , "Any additional info?:"),
    ("poc"     , "Link to PoC video, screenshot, or console output, if any:"),
    ("link"    , "Link to writeup, if any:"),
    ("b64"     , "File contents (base64 encoded please):"),
    ("end"     , "---END BGGPx---"),
]

def cool_input(inText, color="87"):
    """
    This styles the input 
    """
    out = input(f"\x1b[38;5;{color}m{inText}\x1b[0m> ")
    return out

class BGGP:
    def __init__(self, entry_txt_path=None, entry_bin_path=None):
        self.entry_txt_path = entry_txt_path  # path of the BGGP entry
        self.entry_bin_path = entry_bin_path  # path of the binary file to verify
        self.out_path = "bggp.bin"            # Path of the output binary file
        self.verify_out_path = "verified.txt" # Path of the verification stub
        self.entry_txt = "" # Contains the raw text from a BGGP entry
        self.entry_attrs = {} # This contains the attributes for each of the entry elements
        self.b64   = ""   # Base64 of the entry binary data
        self.data  = None # Bytes of the entry binary data
        self.len   = 0    # Length of the entry binary data
        self.hash  = ""   # SHA256 of the entry binary data
    def getSha256(self, inData):
        """
        Pass this function bytes and it will return a hash
        """
        m = hashlib.sha256()
        m.update(inData)
        return m.digest().hex()

    def hexdump(self,inBytes,baseAddr=0):
        """
        Creates a hex dump of data passed to it and returns the buffer
        """
        out = yxd.dump(inBytes, quiet=True)
        return out

    def cleanString(self, in_str):
        """
        Strips leading and trailing newlines and spaces
        """
        in_str = in_str.rstrip()
        in_str = in_str.lstrip()
        return in_str

    def writeBin(self, out_path=""):
        """
        Saves entry binary data to file
        """
        if len(out_path) > 0:
            self.out_path = out_path
        if len(self.data) > 0:
            with open(self.out_path, 'wb') as f:
                f.write(self.data)
                f.close()
                print(f"[+] Saved entry to {self.out_path}!")
        else:
            print("[!] No data to write!")

    def openEntry(self):
        """
        Gets BGGP entry data from file path.
        """
        try:
            with open(self.entry_txt_path, 'r') as f:
                self.entry_txt = f.read()
                print(f"[+] Loaded {self.entry_txt_path}")
        except Exception as e:
            print(e)
            return 1

    def pasteEntry(self):
        """
        Loads an entry based on data pasted from stdin.
        """
        print("[+] Please paste the entry into the terminal!\n")
        found = 0
        while found == 0:
            entry_line = input("") 
            bggp.entry_txt += entry_line + "\n"
            if "---END BGGPx---" in entry_line:
                found = 1
        print("\n[+] Got it!")

    def printAsEntry(self):
        """
        Prints the entry attributes as a BGGP entry
        """
        print(entrys[0][1])
        for e in entrys:
            try:
                print(f"{e[1]} {self.entry_attrs[e[0]]}")
            except KeyError:
                continue
        print(entrys[-1][1])

    def printEntryInfo(self):
        """
        Pretty prints the entry attributes
        """
        table = Table(title="Entry Attributes",
                      box=box.ROUNDED,
                      title_style=color_title,
                      title_justify="left",)
        table.add_column("Key")
        table.add_column("Value")
        for k, v in self.entry_attrs.items():
            if k == "start":
                continue
            table.add_row(k, v)
        print(table)

    def printComputedInfo(self):
        """
        Prints the computed attributes from an entry
        """
        table = Table(title="Computed Attributes",
                      box=box.ROUNDED,
                      title_style=color_title,
                      title_justify="left",)
        table.add_column("Key")
        table.add_column("Value")
        table.add_row("len", str(self.len))
        table.add_row("sha256", self.hash)
        print(table)

    def parseEntry(self):
        """
        Parses an entry and populates self.entry_attrs
        It iterates over the entrys list to get the signatures and attribute name
        """
        fc = self.entry_txt
        i = 0
        for sig in entrys:
            try:
                tmp = fc
                tmp = tmp.split(sig[1])[1] # Split on signature
                tmp = tmp.split(entrys[i+1][1])[0] # Split on next signature
                tmp = self.cleanString(tmp)
                self.entry_attrs[sig[0]] = tmp
                i = i + 1
            except Exception as e:
                #print(e)
                break
        #print(self.entry_attrs) # Debug
        self.b64 = self.entry_attrs["b64"]

        # Get Data from entry
        # TODO: Make this nicer when checking for missing padding!
        if len(self.b64) > 0:
            try:
                self.data = base64.b64decode(self.b64)
            except:
                print("[-] Invalid base64, adding padding '='")
                try:
                    self.data = base64.b64decode(self.b64+"=")
                except:
                    print("[-] Invalid, adding padding '=='")
                    try:
                        self.data = base64.b64decode(self.b64+"==") # if exception occurs here it will just break
                    except:
                        print("[!] Invalid base64!") 

        if len(self.data) > 0:
            self.len = len(self.data)
            print("[+] Added data!")

            # Add the hash
            self.hash = self.getSha256(self.data)
        else:
            print("[!] No base64 found in the entry!")

        # Print Info
        self.printEntryInfo()
        self.printComputedInfo()

    def createEntry(self, inPath=None):
        """
        Creates a BGGP entry. If inPath passed to function, it precomputes some values.
        """
        create_date = datetime.datetime.now()
        create_date = create_date.strftime("%Y-%m-%d")
        self.entry_attrs["date"] = create_date
        self.entry_attrs["chalnum"] = cool_input("BGGP Challenge Number: ")
        self.entry_attrs["author"] = cool_input("Author: ")
        self.entry_attrs["contact"] = cool_input("Contact Info (Optional): ")
        self.entry_attrs["online"] = cool_input("Online Presence (Website/Social Media): ") 
        self.entry_attrs["type"] = cool_input("Target File Type: ")   
        if inPath == None:
            self.entry_attrs["b64"] = cool_input("File contents (base64 encoded please): ")    
            self.entry_attrs["size"] = cool_input("File Size: ")   
            self.entry_attrs["hash"] = cool_input("SHA256 Hash: ")   
        else:
            print("[+] Got file! Processing")
            self.entry_bin_path = inPath
            with open(self.entry_bin_path, "rb") as f:
                self.data = f.read()
                self.len = str(len(self.data))
                self.hash = self.getSha256(self.data)
            self.entry_attrs["b64"] = base64.b64encode(self.data).decode()
            self.entry_attrs["size"] = self.len
            self.entry_attrs["hash"] = self.hash
        self.entry_attrs["env"] = cool_input("Target Environment (How do we run the file?): ")    
        self.entry_attrs["info"] = cool_input("Any additional info?: ")   
        self.entry_attrs["poc"] = cool_input("Link to PoC video, screenshot, or console output, if any: ")    
        self.entry_attrs["link"] = cool_input("Link to writeup, if any: ")
        print()
        self.printAsEntry()

    def verify(self, reviewer="", review_date="", entry_hash="", score=0, note=""):
        """
        Creates a verification stub.

        This is just a simple shell to verify. You can also pass args to this function.
        It parses self.data and populates a verification stub on it. 
        """
        verify_out = ""
        if self.data == None:
            try:
                with open(self.entry_bin_path, 'rb') as f:
                    self.data = f.read()
                    self.len = len(self.data)
            except:
                print("[!] No data or entry path! Please intialize an entry.")
                return
        x = self.hexdump(self.data)
        print(x)
        print()
        if review_date == "":
            review_date = datetime.datetime.now()
            review_date = review_date.strftime("%Y-%m-%d")
        if reviewer == "":
            reviewer = cool_input("Name?")
        if entry_hash == "":
            self.hash = self.getSha256(self.data)
            entry_hash = self.hash
        if score == 0:
            # Put scoring logic in here if needed
            score = self.len
        if note == "":
            note = cool_input("Any notes?")
            if note == "":
                note = "works as is"
        if len(self.entry_txt) > 0:
            verify_out += self.entry_txt
            verify_out += "\n"
        stub = ""
        stub += "---BEGIN VERIFICATION---\n"
        stub += f"Reviewer: {reviewer}\n"
        stub += f"Review Date: {review_date}\n"
        stub += f"SHA256: {entry_hash}\n"
        stub += f"Score: {score}\n" # TODO: Apply score calculations
        stub += f"Note: {note}\n"
        stub += "---END VERIFICATION---\n"
        verify_out += stub
        print()
        print(verify_out)
        with open(self.verify_out_path, "w") as f:
            f.write(verify_out)
            f.close()
            print(f"[+] wrote verification stub to {self.verify_out_path}")

    def printHelp(self):
        """
        Print the BGGP shell help file
        """
        table = Table(title="bggp-tool help",
                      box=box.MINIMAL,
                      title_style=color_title,
                      title_justify="left",)
        table.add_column("Command")
        table.add_column("Description")
        for h in helpfile:
            table.add_row(h[0], h[1])
        print(table)


if __name__ == '__main__':
    print(splash)
    if args.verify_binary:
        bggp = BGGP(entry_bin_path=args.verify_binary)
        bggp.verify()
    elif args.verify_entry:
        bggp = BGGP(entry_txt_path=args.verify_entry)
        bggp.openEntry()
        bggp.parseEntry()
        bggp.verify()
    elif args.create_entry:
        bggp = BGGP()
        bggp.createEntry(inPath=args.create_entry)
    else:
        # BGGP Shell to explore the repo.
        bggp = BGGP()
        while True:
            c = cool_input("BGGP", color="219")
            c = c.split()
            if c == []:
                continue
            elif c[0] == "c":
                if len(c) > 1:
                    bggp.createEntry(inPath=c[1])
                else:
                    bggp.createEntry()
            elif c[0] == "e":
                if len(c) > 1:
                    bggp.entry_txt_path = c[1]
                    bggp.openEntry()
                    bggp.parseEntry()
                else:
                    bggp.pasteEntry()
                    bggp.parseEntry()
            elif c[0] == "i":
                bggp.printEntryInfo()
                bggp.printComputedInfo()
            elif c[0] == "r":
                print("[+] Resetting entry!")
                bggp = BGGP()
            elif c[0] == "s":
                if len(c) > 1:
                    bggp.writeBin(out_path=c[1])
                else:
                    bggp.writeBin()
            elif c[0] == "v":
                print("[+] Verifying entry!")
                bggp.verify()
            elif c[0] == "x":
                exit()
            else:
                bggp.printHelp()
