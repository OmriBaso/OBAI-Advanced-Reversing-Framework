"""Entry point for the OBAI Reverse Engineering Platform."""

import os
from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True,
    )
