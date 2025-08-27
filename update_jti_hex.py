from pymongo import MongoClient
import uuid

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['flashcarddb']  # Replace with your database name

# Collection name
collection = db['token_blacklist_outstandingtoken']

# Find documents where jti_hex is null, missing, or an empty string
documents = collection.find({"$or": [{"jti_hex": None}, {"jti_hex": ""}]})

# Count the number of documents with jti_hex null or empty
count = collection.count_documents({"$or": [{"jti_hex": None}, {"jti_hex": ""}]})
print(f"Found {count} documents with jti_hex as null or empty.")

# Update documents with a unique jti_hex value
updated_count = 0
for doc in documents:
    new_jti_hex = uuid.uuid4().hex
    collection.update_one({"_id": doc["_id"]}, {"$set": {"jti_hex": new_jti_hex}})
    updated_count += 1

print(f"Updated {updated_count} documents with new jti_hex values.")
