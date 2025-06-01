from daytona_sdk import Daytona, DaytonaConfig, CreateSandboxParams

# Initialize the Daytona client
daytona = Daytona(DaytonaConfig(api_key="dtn_14033978ed8214ab78d3993007b8bd1cdcb0eac6dcb9cd6cac609049c8d2161e"))

# Create the Sandbox instance
sandbox = daytona.create(CreateSandboxParams(
    image="kortix/suna:0.1.2",
    public=True,
    labels={"name": "test"},  # Changed from string to dictionary
    env_vars={
        "CHROME_PERSISTENT_SESSION": "true",
        "RESOLUTION": "1024x768x24",
        "RESOLUTION_WIDTH": "1024",
        "RESOLUTION_HEIGHT": "768",
        "VNC_PASSWORD": "test_password",
        "ANONYMIZED_TELEMETRY": "false",
        "CHROME_PATH": "",
        "CHROME_USER_DATA": "",
        "CHROME_DEBUGGING_PORT": "9222",
        "CHROME_DEBUGGING_HOST": "localhost",
        "CHROME_CDP": ""
    },
    resources={
        "cpu": 2,
        "memory": 4,
        "disk": 5,
    }
))