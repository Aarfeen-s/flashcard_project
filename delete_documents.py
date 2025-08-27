# delete_documents.py

import os
import django
from pymongo import MongoClient
from django.conf import settings

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'flashapi.settings')
django.setup()

from Flash.models import Questions  # Import your Django model

def delete_documents():
    try:
        # Get IDs of objects where id is None
        object_ids = list(Questions.objects.filter(id=None).values_list('_id', flat=True))

        # Ensure there are IDs to delete
        if not object_ids:
            print("No documents found with id as None.")
            return

        # Connect to MongoDB using the URI from Django settings
        mongo_uri = settings.DATABASES['default']['HOST']
        client = MongoClient(mongo_uri)
        db = client.get_database(settings.DATABASES['default']['NAME'])  # Use the database name from Django settings
        collection_name = 'Flash_questions'  # Replace with your actual collection name
        collection = db.get_collection(collection_name)

        # Delete documents using _id values
        result = collection.delete_many({'_id': {'$in': object_ids}})
        print(f"{result.deleted_count} documents deleted from MongoDB collection '{collection_name}'.")

    except Exception as e:
        print(f"Error deleting documents from MongoDB: {str(e)}")

    finally:
        # Close the MongoDB client connection
        client.close()

if __name__ == "__main__":
    delete_documents()
