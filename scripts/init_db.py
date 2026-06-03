from app.config import settings
from app.db import SnapshotStore

if __name__ == "__main__":
    store = SnapshotStore(settings.database_url)
    try:
        print(store.init_db())
    finally:
        store.close()
