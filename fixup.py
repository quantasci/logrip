
def remove_after_mozilla(infile_path, outfile_path):
    with open(infile_path, 'r', encoding='utf-8') as infile, \
         open(outfile_path, 'w', encoding='utf-8') as outfile:
        
        for line in infile:
            idx = line.find("Mozilla")
            if idx != -1:
                cleaned = line[:idx].rstrip()
            else:
                cleaned = line.rstrip()
            outfile.write(cleaned + '\n')

# Example usag
remove_after_mozilla("ramakarl_master.txt", "ramakarl_new.txt")
