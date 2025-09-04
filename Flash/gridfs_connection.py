from pymongo import MongoClient
import gridfs

# ✅ Adjust DB name to match your project
client = MongoClient("mongodb://127.0.0.1:27017/")
db = client["New_Testing"]

# ✅ Create GridFS bucket
fs = gridfs.GridFS(db)