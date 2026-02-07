
print("Starting import debug...")
try:
    import sys
    import os
    # Add current directory to path
    sys.path.append(os.getcwd())
    
    print("Importing controller.tasks...")
    from controller import tasks
    print("Import successful!")
except Exception as e:
    print(f"Import failed: {e}")
    import traceback
    traceback.print_exc()
