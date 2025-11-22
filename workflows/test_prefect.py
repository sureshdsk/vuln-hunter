
try:
    import prefect
    print(f"Prefect version: {prefect.__version__}")
    from prefect import flow
    print("Successfully imported flow")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
