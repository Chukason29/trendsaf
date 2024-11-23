
import csv
import pendulum
import random

# Specify the CSV file name
file_name = "products.csv"

# Define the headers for the CSV file
headers = ["product_id", "crop_variety_id", "country_id", "price", "created_at", "region_id"]

# Generate sample data
sample_data = [
    {
        "product_id": i + 1,  # Auto-incrementing ID
        "crop_variety_id": random.randint(1, 8),
        "country_id": random.randint(1, 4),
        "price": random.randint(50, 1000),
        "created_at": pendulum.now("UTC").subtract(days=random.randint(0, 30)).to_iso8601_string(),
        "region_id": random.randint(1, 4)
    }
    for i in range(100)  # Generate 20 rows of sample data
]

# Write the data to the CSV file
with open(file_name, mode="w", newline="", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=headers)
    
    # Write the header row
    writer.writeheader()
    
    # Write the data rows
    writer.writerows(sample_data)

print(f"CSV file '{file_name}' has been created and populated successfully.")