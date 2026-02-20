"""Dungeoncore — Entry Point.

Aufruf:
  python dungeoncore.py init
  python dungeoncore.py unlock
  python dungeoncore.py lock
  python dungeoncore.py status
  python dungeoncore.py add KEY_NAME
  python dungeoncore.py get KEY_NAME
  python dungeoncore.py list
  python dungeoncore.py remove KEY_NAME
"""

from src.dungeoncore.cli import main

if __name__ == "__main__":
    main()
