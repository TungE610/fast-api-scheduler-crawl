import csv

def add_index_to_csv(input_file: str, output_file: str):
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        rows = list(reader)

    if not rows:
        raise ValueError("The input CSV file is empty.")

    # Add header for index column
    headers = ['id'] + rows[0]

    with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(headers)
        
        for index, row in enumerate(rows[1:], start=1):  # Skip header row
            writer.writerow([index] + row)

# Usage
input_csv = 'file/phishing_data.csv'
output_csv = 'file/phishing_data.csv'
add_index_to_csv(input_csv, output_csv)
print(f"Index added and new file saved as {output_csv}")