
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


def every_nth_line(infile_path, outfile_path, N):
    if N <= 0:
        raise ValueError("N must be greater than 0")

    with open(infile_path, 'r', encoding='utf-8') as infile, \
         open(outfile_path, 'w', encoding='utf-8') as outfile:
        
        for idx, line in enumerate(infile):
            if idx % N == 0:
                outfile.write(line)

# Example usage

# remove_after_mozilla("ramakarl_master.txt", "ramakarl_new.txt")

every_nth_line("ramakarl_new.txt", "ramakarl_new2.txt", 4 )
