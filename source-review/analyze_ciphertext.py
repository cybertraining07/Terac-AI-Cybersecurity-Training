
from collections import Counter

file_path = (
    "../evidence/announcement_encrypted.md"
)

with open(file_path, "r") as file:
    values = [line.strip() for line in file if line.strip()]

counts = Counter(values)

print("Total ciphertext values:", len(values))
print("Unique ciphertext values:", len(counts))

print("\nRepeated ciphertext values:")
for value, count in counts.most_common(10):
    if count > 1:
        print(f"{value[:35]}... appears {count} times")
