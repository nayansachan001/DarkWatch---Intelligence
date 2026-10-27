import os

from dotenv import load_dotenv
from pymongo import MongoClient, DESCENDING


load_dotenv()


def connect_database():
    """Connect to MongoDB Atlas and return the client and collection."""
    uri = "mongodb+srv://nayansachan8081_db_user:Nayansachan9936@darkwatch.dvssvcu.mongodb.net/"

    if not uri:
        raise RuntimeError(
            "MONGODB_URI is missing. Check your local .env file."
        )

    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=7000,
        tz_aware=True,
        appname="DarkWatch",
    )

    # Verify the connection now rather than during the first insert.
    client.admin.command("ping")

    database = client["darkwatch"]
    collection = database["observations"]

    # Make historical queries by website and time more efficient.
    collection.create_index(
        [("target_url", 1), ("checked_at", DESCENDING)]
    )

    return client, collection


def get_previous_fingerprint(collection, target_url):
    """Get the most recent complete HTML fingerprint for this target."""
    previous = collection.find_one(
        {
            "target_url": target_url,
            "fingerprint_complete": True,
            "content_hash": {"$type": "string"},
        },
        {"content_hash": 1, "_id": 0},
        sort=[("checked_at", DESCENDING)],
    )

    return previous["content_hash"] if previous else None


def save_observation(collection, record):
    """Insert one monitoring observation."""
    collection.insert_one(record)


def load_recent_observations(collection, target_url, limit=100):
    """Load recent records for a specific website."""
    cursor = (
        collection.find(
            {"target_url": target_url},
            {"_id": 0},
        )
        .sort("checked_at", DESCENDING)
        .limit(limit)
    )

    return list(cursor)